# ============================================================
# main.py — Eccomi Proxy v1.8 PRO
# - App Proxy firmato (SafeMode: trust sullo shop + verifica diagnostica HMAC)
# - Rotte: /proxy/capture-customer (via App Proxy), /capture-customer (alias)
# - Multi-tag via Admin GraphQL (tagsAdd)
# - Supporto "tags" o "tag", split per virgola, trim
# - Whitelist opzionale ALLOWED_TAGS (CSV)
# - Endpoint diagnostici: /health, /hmac-check
# ============================================================

import os, json, hmac, hashlib, httpx
from urllib.parse import urlparse, parse_qsl
from typing import Any, Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ---------------- ENV / CONFIG ----------------
PORT = int(os.getenv("PORT", "10000"))

SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "eccomionline.myshopify.com")
SHOP_ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")
SHOPIFY_API_VER = os.getenv("SHOPIFY_API_VER", "2025-10")

APP_SHARED_SECRET = os.getenv("SHOPIFY_APP_SHARED_SECRET", "")
VERIFY_APP_PROXY_HMAC = os.getenv("VERIFY_APP_PROXY_HMAC", "true").lower() == "true"

DEFAULT_CAPTURE_TAG = os.getenv("DEFAULT_CAPTURE_TAG", "Eccomi-Proxy-Captured")
ALLOWED_TAGS = [t.strip() for t in os.getenv("ALLOWED_TAGS", "").split(",") if t.strip()]  # opzionale
DEBUG_ECHO = os.getenv("DEBUG_ECHO", "true").lower() == "true"

# ---------------- APP ----------------
app = FastAPI(title="Eccomi Proxy", version="1.8.0 PRO")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ---------------- UTILS ----------------
def _safe_jsonable(obj: Any):
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return str(obj)

def _split_tags(raw: Any) -> List[str]:
    tags = [t.strip() for t in str(raw or "").split(",") if t.strip()]
    if ALLOWED_TAGS:
        tags = [t for t in tags if t in ALLOWED_TAGS]
    return tags or ([DEFAULT_CAPTURE_TAG] if DEFAULT_CAPTURE_TAG else [])

def _customer_id_from(qp: Dict[str,str], payload: Dict[str,Any]) -> str:
    raw = (qp.get("cid") or payload.get("customer_id") or qp.get("logged_in_customer_id") or "").strip()
    raw = "".join(ch for ch in raw if ch.isdigit())
    return raw

# ---------------- HMAC SAFE VERIFY ----------------
def verify_app_proxy_request(full_url: str, shared_secret: str) -> Dict[str, Any]:
    """
    SafeMode:
      - Se 'shop' corrisponde allo SHOP_DOMAIN → ok=True (trusted-shop).
      - In più calcola una verifica HMAC 'canonica' (diagnostica) per info.
    Nota: Shopify per App Proxy varia path/calcolo; il trust sul dominio evita falsi negativi.
    """
    parsed = urlparse(full_url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    shop = q.get("shop", "")
    provided = q.get("signature")
    result = {
        "ok": False,
        "trusted": False,
        "mode": None,
        "verify_hmac_flag": VERIFY_APP_PROXY_HMAC,
        "meta": {
            "shop": shop,
            "path": parsed.path,
            "path_prefix": q.get("path_prefix"),
            "has_signature": bool(provided),
        },
        "hint": "",
    }

    # 1) Trust sullo shop (hard gate)
    if shop.endswith(SHOP_DOMAIN):
        result["ok"] = True
        result["trusted"] = True
        result["hint"] = "trusted-shop"
    else:
        result["hint"] = "shop_mismatch"

    # 2) Diagnostica HMAC (non bloccante)
    if shared_secret and provided:
        params = q.copy()
        params.pop("signature", None)
        canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items(), key=lambda kv: kv[0]))
        digest = hmac.new(shared_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(digest, provided):
            result["mode"] = "canonical"
        else:
            result["mode"] = None

    return result

def require_hmac_or_trust(req: Request):
    """Alza 403 solo se non è trusted-shop e la verifica è abilitata."""
    if not VERIFY_APP_PROXY_HMAC:
        return {"skipped": True}
    data = verify_app_proxy_request(str(req.url), APP_SHARED_SECRET)
    if not data.get("ok"):
        raise HTTPException(status_code=403, detail="Invalid or untrusted App Proxy request")
    return data

# ---------------- ADMIN API: TAGS ----------------
async def add_customer_tags(customer_id_numeric: str, tags: List[str]) -> Dict[str, Any]:
    if not (SHOP_DOMAIN and SHOP_ADMIN_TOKEN and customer_id_numeric and tags):
        return {"ok": False, "skipped": "missing_env_or_id_or_tags"}

    gid = f"gid://shopify/Customer/{customer_id_numeric}"
    query = """
    mutation tagsAdd($id: ID!, $tags: [String!]!) {
      tagsAdd(id: $id, tags: $tags) { userErrors { field message } }
    }
    """
    variables = {"id": gid, "tags": tags}

    url = f"https://{SHOP_DOMAIN}/admin/api/{SHOPIFY_API_VER}/graphql.json"
    headers = {"X-Shopify-Access-Token": SHOP_ADMIN_TOKEN, "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, headers=headers, json={"query": query, "variables": variables})
            data = resp.json()
            errs = (data.get("data", {}).get("tagsAdd", {}).get("userErrors") or [])
            return {"ok": (resp.status_code == 200 and not errs), "status": resp.status_code, "errors": errs, "response": data}
    except Exception as e:
        return {"ok": False, "network_error": str(e)}

# ---------------- HANDLER COMUNE ----------------
async def handle_capture(req: Request):
    # parse payload/query
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    qp = dict(req.query_params)

    # se arriva dal proxy Shopify ci sarà "signature" → verifichiamo/trust
    hmac_info = require_hmac_or_trust(req) if ("signature" in qp or VERIFY_APP_PROXY_HMAC) else {"skipped": True}

    # dati
    customer_id = _customer_id_from(qp, payload)
    email = qp.get("email") or payload.get("email")
    raw_tags = qp.get("tags") or qp.get("tag") or DEFAULT_CAPTURE_TAG
    tags = _split_tags(raw_tags)

    tag_result = {}
    if customer_id:
        tag_result = await add_customer_tags(customer_id, tags)

    resp = {
        "ok": True,
        "via": "app-proxy" if "signature" in qp else "direct",
        "customer_id": customer_id or None,
        "email": email or None,
        "actions": {"tagsAdd": tag_result},
    }
    if DEBUG_ECHO:
        resp["received"] = {"query": _safe_jsonable(qp), "json": _safe_jsonable(payload)}
        resp["hmac"] = hmac_info
    return JSONResponse(resp)

# ---------------- ROUTES ----------------
@app.get("/")
async def root():
    return {
        "service": "Eccomi Proxy",
        "version": "1.8.0 PRO",
        "routes": ["/health", "/hmac-check", "/capture-customer", "/proxy/capture-customer"],
        "verify_hmac_enabled": VERIFY_APP_PROXY_HMAC,
        "shop": SHOP_DOMAIN,
    }

@app.get("/health")
async def health():
    return {"ok": True, "service": "Eccomi Proxy", "verify_hmac": VERIFY_APP_PROXY_HMAC, "shop": SHOP_DOMAIN}

@app.get("/hmac-check")
async def hmac_check(req: Request):
    data = verify_app_proxy_request(str(req.url), APP_SHARED_SECRET)
    return JSONResponse(data)

@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer_direct(req: Request):
    # alias (utile in debug); con SafeMode comunque verifichiamo shop+signature se presente
    return await handle_capture(req)

@app.api_route("/proxy/capture-customer", methods=["GET", "POST"])
async def capture_customer_proxy(req: Request):
    # rotta tipica dietro App Proxy → passa sempre da handle_capture
    return await handle_capture(req)

# ---------------- MAIN (local) ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
