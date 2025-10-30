# main.py — Eccomi Proxy v1.5 (completo)
# - App Proxy: /proxy, /proxy/capture-customer
# - Alias diretto: /capture-customer
# - Fallback customer id: logged_in_customer_id
# - HMAC App Proxy opzionale
# - Aggiunta tag cliente via Admin GraphQL

import os
import hmac
import hashlib
from urllib.parse import urlparse, parse_qsl
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json

# =========================
# ENV / CONFIG
# =========================
PORT = int(os.getenv("PORT", "10000"))

# Sicurezza App Proxy
APP_SHARED_SECRET = os.getenv("SHOPIFY_APP_SHARED_SECRET", "")
VERIFY_APP_PROXY_HMAC = os.getenv("VERIFY_APP_PROXY_HMAC", "false").lower() == "true"

# Admin API per tag cliente
SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "")  # es: eccomionline.myshopify.com
SHOP_ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")
SHOPIFY_API_VER = os.getenv("SHOPIFY_API_VER", "2024-10")  # ok anche 2025-10

# Comportamento
DEFAULT_CAPTURE_TAG = os.getenv("DEFAULT_CAPTURE_TAG", "Eccomi-Proxy-Captured")
DEBUG_ECHO = os.getenv("DEBUG_ECHO", "true").lower() == "true"  # include query/meta in risposta

# =========================
# APP
# =========================
app = FastAPI(title="Eccomi Proxy", version="1.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# UTILS
# =========================
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
    Verifica HMAC App Proxy (signature in query).
    Calcolo: HMAC-SHA256 su 'k=v&k=v...' dei params ordinati (senza 'signature').
    """
    if not shared_secret:
        return False
    parsed = urlparse(full_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    provided = params.get("signature", "")
    digest = hmac.new(
        shared_secret.encode("utf-8"),
        _sorted_qs_without_signature(params).encode("utf-8"),
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
    """
    Ordine di precedenza:
    1) cid esplicito
    2) customer_id nel body
    3) logged_in_customer_id aggiunto da Shopify App Proxy
    Valida numerico/positivo.
    """
    raw = (qp.get("cid") or payload.get("customer_id") or qp.get("logged_in_customer_id") or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return raw
    return ""

def base_meta(qp: Dict[str, str]) -> Dict[str, Any]:
    """
    Meta utili che Shopify include nel proxy:
    - shop
    - logged_in_customer_id
    - path_prefix
    - timestamp
    - signature (se HMAC attivo lato Shopify)
    """
    keys = ["shop", "logged_in_customer_id", "path_prefix", "timestamp", "signature"]
    return {k: qp.get(k) for k in keys if k in qp}

# =========================
# ROUTES: BASE
# =========================
@app.get("/")
async def root():
    return {
        "service": "Eccomi Proxy",
        "docs": "/docs",
        "health": "/health",
        "proxy_root": "/proxy",
        "capture": ["/capture-customer", "/proxy/capture-customer"],
        "verify_hmac": VERIFY_APP_PROXY_HMAC,
        "status": "online ✅"
    }

@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "Eccomi Proxy",
        "verify_hmac": VERIFY_APP_PROXY_HMAC,
        "shop_domain": SHOP_DOMAIN or None
    }

@app.get("/proxy")
async def proxy_root():
    # Ping del mapping /apps/<subpath>
    return {"ok": True, "service": "Eccomi Proxy", "hint": "mapping OK (Shopify → /apps/<subpath>)"}

# =========================
# HANDLER COMUNE
# =========================
async def handle_capture(req: Request, via: str):
    try:
        payload = await req.json()
        if payload is None:
            payload = {}
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
        response["received"] = {
            "query": _safe_jsonable(qp),
            "json": _safe_jsonable(payload),
        }
        response["meta"] = base_meta(qp)

    return JSONResponse(response)

# =========================
# ROUTES: CAPTURE
# =========================
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer_direct(req: Request):
    # Alias “diretto” (senza App Proxy) — utile per test/server-to-server
    return await handle_capture(req, via="direct")

@app.api_route("/proxy/capture-customer", methods=["GET", "POST"])
async def capture_customer_proxy(req: Request):
    # Versione proxata dal sito: /apps/<subpath>/capture-customer
    return await handle_capture(req, via="app-proxy")

# =========================
# MAIN (locale)
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
