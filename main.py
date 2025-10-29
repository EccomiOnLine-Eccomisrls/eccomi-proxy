# main.py — Eccomi Proxy (FastAPI)
# v1.3.0 — App Proxy + Consensi + Test endpoint

import os
import hmac
import hashlib
import urllib.parse
import httpx

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# ========= ENV =========
SHOP_DOMAIN         = os.getenv("SHOP_DOMAIN", "")
SHOP_ADMIN_TOKEN    = os.getenv("SHOP_ADMIN_TOKEN", "")
API_VER             = os.getenv("SHOPIFY_API_VER", "2025-10")  # ok anche 2024-10
SHOPIFY_API_SECRET  = os.getenv("SHOPIFY_API_SECRET", "")      # per firma App Proxy
VERIFY_APP_PROXY    = os.getenv("VERIFY_APP_PROXY", "true").lower() == "true"
ALLOWED_TAGS_ENV    = os.getenv("ALLOWED_TAGS", "Consent:1,Consent:2,Consent:3,Eccomi:Registered")

app = FastAPI(title="Eccomi Proxy", version="1.3.0")

# ========= UTILITY =========
def _require_env():
    if not SHOP_DOMAIN or not SHOP_ADMIN_TOKEN:
        raise HTTPException(500, "Missing SHOP_DOMAIN or SHOP_ADMIN_TOKEN")

def _allowed_tags_list() -> list[str]:
    return [t.strip() for t in ALLOWED_TAGS_ENV.split(",") if t.strip()]

def verify_app_proxy_request(full_url: str) -> None:
    """
    Verifica la firma App Proxy.
    Supporta:
      - 'signature' (schema app proxy ufficiale: sha256(secret + concatenated key=value))
      - fallback 'hmac' (sha256-HMAC su querystring urlencoded)
    """
    if not VERIFY_APP_PROXY:
        return
    if not SHOPIFY_API_SECRET:
        raise HTTPException(401, "Missing SHOPIFY_API_SECRET")

    parts = urllib.parse.urlsplit(full_url)
    qs = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))

    # 1) Schema 'signature'
    signature = qs.pop("signature", None)
    if signature:
        payload = "".join(f"{k}={v}" for k, v in sorted(qs.items()))
        digest = hashlib.sha256((SHOPIFY_API_SECRET + payload).encode("utf-8")).hexdigest()
        if digest != signature:
            raise HTTPException(401, "Bad app proxy signature")
        return

    # 2) Fallback 'hmac'
    hmac_qs = qs.pop("hmac", None)
    if hmac_qs:
        message = urllib.parse.urlencode(sorted(qs.items()))
        digest = hmac.new(SHOPIFY_API_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        if digest != hmac_qs:
            raise HTTPException(401, "Bad app proxy hmac")
        return

    raise HTTPException(401, "Missing app proxy signature")

async def admin_graphql(query: str, variables: dict | None = None) -> dict:
    _require_env()
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_VER}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(url, headers=headers, json={"query": query, "variables": variables or {}})
    if r.status_code >= 300:
        raise HTTPException(r.status_code, f"Admin GraphQL error: {r.text}")
    return r.json()

async def add_customer_tag(customer_id_numeric: str, tag: str) -> dict:
    """Tag singolo (comodo per test)."""
    if not (SHOP_DOMAIN and SHOP_ADMIN_TOKEN and customer_id_numeric):
        return {"ok": False, "skipped": "missing_admin_env_or_id"}
    gid = f"gid://shopify/Customer/{customer_id_numeric}"
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_VER}/graphql.json"
    query = """
      mutation TagCustomer($id: ID!, $tags: [String!]!) {
        tagsAdd(id: $id, tags: $tags) { userErrors { field message } }
      }
    """
    variables = {"id": gid, "tags": [tag]}
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json={"query": query, "variables": variables}, headers=headers)
        data = r.json()
    ok = (r.status_code == 200) and not data.get("data",{}).get("tagsAdd",{}).get("userErrors")
    return {"ok": ok, "status": r.status_code, "data": data}

async def add_customer_tags(customer_id_numeric: str, tags: list[str]) -> dict:
    """Multi-tag in una sola chiamata."""
    if not (SHOP_DOMAIN and SHOP_ADMIN_TOKEN and customer_id_numeric and tags):
        return {"ok": False, "skipped": "missing_env_or_params"}
    gid = f"gid://shopify/Customer/{customer_id_numeric}"
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_VER}/graphql.json"
    query = """
      mutation TagCustomer($id: ID!, $tags: [String!]!) {
        tagsAdd(id: $id, tags: $tags) { userErrors { field message } }
      }
    """
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json={"query": query, "variables": {"id": gid, "tags": tags}}, headers=headers)
    data = r.json()
    ok = (r.status_code == 200) and not data.get("data",{}).get("tagsAdd",{}).get("userErrors")
    return {"ok": ok, "status": r.status_code, "data": data}

# ========= ENDPOINTS =========
@app.get("/")
async def root():
    return {
        "service": "Eccomi Proxy",
        "version": app.version,
        "health": "/health",
        "test_capture": "/capture-customer",
        "proxy_capture": "/proxy/capture-customer"
    }

@app.get("/health")
async def health():
    return {"ok": True}

# --- Endpoint di TEST: non deve mai esplodere (utile per capire se il proxy funziona) ---
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer(request: Request):
    try:
        headers = {k.lower(): v for k, v in request.headers.items()}
        proxied = headers.get("x-shopify-proxy-request", "NO")  # "1" quando passa via App Proxy
        qs = dict(request.query_params)

        cid = qs.get("cid") or qs.get("logged_in_customer_id")
        email = qs.get("email")

        tag_result = None
        # tagga un marker solo se è davvero via App Proxy e abbiamo l'id
        if proxied == "1" and cid:
            tag_result = await add_customer_tag(cid, "EccomiProxy-Seen")

        return JSONResponse({
            "ok": True,
            "msg": "Eccomi Proxy READY ✅",
            "proxied": "1" if proxied == "1" else "NO",
            "qs": qs,
            "customer_id": cid,
            "email": email,
            "tag_result": tag_result
        }, status_code=200)
    except Exception as e:
        # rispondiamo 200 comunque per non rompere il front
        return JSONResponse({"ok": False, "error": str(e)}, status_code=200)

# --- App Proxy: cattura consensi e applica TAG (ufficiale) ---
@app.api_route("/proxy/capture-customer", methods=["POST", "GET"])
async def proxy_capture_customer(req: Request):
    try:
        # 1) Verifica firma App Proxy
        verify_app_proxy_request(str(req.url))

        # 2) Payload
        if req.method == "POST":
            try:
                body = await req.json()
            except:
                body = {}
        else:
            body = {}

        qs = dict(req.query_params)
        cid   = str(body.get("customer_id") or qs.get("customer_id") or qs.get("cid") or qs.get("logged_in_customer_id") or "")
        email = (body.get("email") or qs.get("email") or "").strip()

        # tags: JSON ["Consent:1", ...] OPPURE GET ?tags=Consent:1,Consent:2
        tags_in = body.get("tags")
        if tags_in is None and "tags" in qs:
            tags_in = [t.strip() for t in qs["tags"].split(",") if t.strip()]
        tags_in = tags_in or []

        if not cid:
            return JSONResponse({"ok": False, "error": "Missing customer_id"}, status_code=400)

        # 3) Whitelist di sicurezza
        allowed = set(_allowed_tags_list())
        tags = [t for t in tags_in if t in allowed]

        if not tags:
            return JSONResponse({"ok": True, "note": "no allowed tags to apply", "customer_id": cid}, status_code=200)

        # 4) Applica i tag
        res = await add_customer_tags(cid, tags)
        return JSONResponse({"ok": True, "applied": tags, "apply_result": res, "customer_id": cid, "email": email}, status_code=200)

    except Exception as e:
        # mai 500: rispondiamo 200 con errore per non bloccare il front
        return JSONResponse({"ok": False, "error": str(e)}, status_code=200)
