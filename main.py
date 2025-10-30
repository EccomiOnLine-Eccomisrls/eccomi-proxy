# ============================================================
# main.py — Eccomi Proxy v1.6 (completo)
# ============================================================
# - App Proxy: /proxy, /proxy/capture-customer
# - Alias diretto: /capture-customer
# - Fallback customer id: logged_in_customer_id
# - HMAC App Proxy opzionale (firma Shopify)
# - Aggiunta tag cliente via Admin GraphQL
# - Endpoint diagnostici: /health, /hmac-check
# ============================================================

import os, hmac, hashlib, json, httpx
from urllib.parse import urlparse, parse_qsl
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# ENV / CONFIG
# ============================================================
PORT = int(os.getenv("PORT", "10000"))

# Sicurezza App Proxy
APP_SHARED_SECRET = os.getenv("SHOPIFY_APP_SHARED_SECRET", "")
VERIFY_APP_PROXY_HMAC = os.getenv("VERIFY_APP_PROXY_HMAC", "false").lower() == "true"

# Admin API per tag cliente
SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "")
SHOP_ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")
SHOPIFY_API_VER = os.getenv("SHOPIFY_API_VER", "2025-10")

# Comportamento
DEFAULT_CAPTURE_TAG = os.getenv("DEFAULT_CAPTURE_TAG", "Eccomi-Proxy-Captured")
DEBUG_ECHO = os.getenv("DEBUG_ECHO", "true").lower() == "true"

# ============================================================
# APP INIT
# ============================================================
app = FastAPI(title="Eccomi Proxy", version="1.6.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# UTILS
# ============================================================
def _safe_jsonable(obj: Any):
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return str(obj)

def _sorted_qs_without_signature(params: Dict[str, str]) -> str:
    items = [(k, v) for k, v in params.items() if k != "signature"]
    items.sort(key=lambda x: x[0])
    return "&".join(f"{k}={v}" for k, v in items)

def verify_app_proxy_request(full_url: str, shared_secret: str) -> bool:
    """
    Verifica HMAC App Proxy (Shopify): HMAC-SHA256 di
    '<path>?<query_ordinata_senza_signature>'
    """
    if not shared_secret:
        return False
    parsed = urlparse(full_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    provided = params.pop("signature", None)
    if not provided:
        return False
    qs = _sorted_qs_without_signature(params)
    msg = f"{parsed.path}?{qs}" if qs else f"{parsed.path}?"
    digest = hmac.new(
        shared_secret.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(digest, provided)

async def add_customer_tag(customer_id_numeric: str, tag: str) -> Dict[str, Any]:
    """
    Aggiunge un tag al customer via Admin GraphQL.
    """
    if not (SHOP_DOMAIN and SHOP_ADMIN_TOKEN and customer_id_numeric):
        return {"ok": False, "skipped": "missing_admin_env_or_id"}

    gid = f"gid://shopify/Customer/{customer_id_numeric}"
    query = """
    mutation tagsAdd($id: ID!, $tags: [String!]!) {
      tagsAdd(id: $id, tags: $tags) {
        node { id }
        userErrors { field message }
      }
    }
    """
    variables = {"id": gid, "tags": [tag]}
    url = f"https://{SHOP_DOMAIN}/admin/api/{SHOPIFY_API_VER}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, json={"query": query, "variables": variables})
        data = resp.json()
        errs = (data.get("data", {}).get("tagsAdd", {}).get("userErrors") or [])
        return {
            "ok": (resp.status_code == 200 and not errs),
            "status": resp.status_code,
            "errors": errs,
            "response": data,
        }

def extract_customer_id(qp: Dict[str, str], payload: Dict[str, Any]) -> str:
    raw = (qp.get("cid") or payload.get("customer_id") or qp.get("logged_in_customer_id") or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return raw
    return ""

def base_meta(qp: Dict[str, str]) -> Dict[str, Any]:
    keys = ["shop", "logged_in_customer_id", "path_prefix", "timestamp", "signature"]
    return {k: qp.get(k) for k in keys if k in qp}

# ============================================================
# ROUTES BASE
# ============================================================
@app.get("/")
async def root():
    return {
        "service": "Eccomi Proxy",
        "version": "1.6.0",
        "docs": "/docs",
        "health": "/health",
        "hmac_check": "/hmac-check",
        "capture": ["/capture-customer", "/proxy/capture-customer"],
        "verify_hmac_enabled": VERIFY_APP_PROXY_HMAC,
        "status": "online ✅"
    }

@app.get("/health")
async def health():
    return {"ok": True, "service": "Eccomi Proxy", "verify_hmac": VERIFY_APP_PROXY_HMAC, "shop": SHOP_DOMAIN or None}

@app.get("/proxy")
async def proxy_root():
    return {"ok": True, "service": "Eccomi Proxy", "hint": "mapping OK (Shopify → /apps/<subpath>)"}

# ============================================================
# HANDLER COMUNE
# ============================================================
async def handle_capture(req: Request, via: str):
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    qp = dict(req.query_params)

    # HMAC per chiamate App Proxy
    if via == "app-proxy" and VERIFY_APP_PROXY_HMAC:
        if not verify_app_proxy_request(str(req.url), APP_SHARED_SECRET):
            raise HTTPException(status_code=403, detail="Invalid app proxy signature")

    customer_id = extract_customer_id(qp, payload)
    email = qp.get("email") or payload.get("email")
    tag = qp.get("tag") or DEFAULT_CAPTURE_TAG

    tag_result = {}
    if customer_id:
        tag_result = await add_customer_tag(customer_id, tag)

    response: Dict[str, Any] = {
        "ok": True,
        "via": via,
        "customer_id": customer_id or None,
        "email": email or None,
        "actions": {"tag_customer": tag_result},
    }

    if DEBUG_ECHO:
        response["received"] = {"query": _safe_jsonable(qp), "json": _safe_jsonable(payload)}
        response["meta"] = base_meta(qp)

    return JSONResponse(response)

# ============================================================
# ROUTES CAPTURE
# ============================================================
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer_direct(req: Request):
    return await handle_capture(req, via="direct")

@app.api_route("/proxy/capture-customer", methods=["GET", "POST"])
async def capture_customer_proxy(req: Request):
    return await handle_capture(req, via="app-proxy")

# ============================================================
# DIAGNOSTICA HMAC
# ============================================================
@app.get("/hmac-check")
async def hmac_check(req: Request):
    if not VERIFY_APP_PROXY_HMAC:
        return JSONResponse({
            "ok": True,
            "verify_hmac_flag": False,
            "hint": "verifica HMAC disattivata (debug)"
        })

    ok = verify_app_proxy_request(str(req.url), APP_SHARED_SECRET)
    return JSONResponse({
        "ok": ok,
        "verify_hmac_flag": True,
        "meta": base_meta(dict(req.query_params)),
        "hint": "firma App Proxy valida" if ok else "firma mancante/non valida"
    })

# ============================================================
# MAIN (locale)
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
