# main.py — Eccomi Proxy + Capture Customer v1.3
# Continua i ragionamenti già fatti: health, alias /capture-customer,
# App Proxy Shopify (/proxy, /proxy/capture-customer), HMAC opzionale,
# add tag cliente via Admin GraphQL (se token presente).

import os
import hmac
import hashlib
import base64
import json
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qsl, urlencode

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

# ========= ENV =========
APP_SHARED_SECRET = os.getenv("SHOPIFY_APP_SHARED_SECRET", "")  # Shared secret dell'app
VERIFY_APP_PROXY_HMAC = os.getenv("VERIFY_APP_PROXY_HMAC", "false").lower() == "true"

SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "")  # p.es. eccomionline.myshopify.com
SHOP_ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")  # Admin API access token (GraphQL Admin)

API_VER = os.getenv("SHOPIFY_API_VER", "2024-10")  # ok anche 2025-10
DEFAULT_TAG = os.getenv("DEFAULT_CAPTURE_TAG", "Eccomi-Proxy-Captured")

PORT = int(os.getenv("PORT", "10000"))

# ========= APP =========
app = FastAPI(title="Eccomi Proxy", version="1.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= UTILS =========
def sort_params_for_signature(params: Dict[str, str]) -> str:
    """Ordina i parametri (escludendo 'signature') e li concatena 'k=v' uniti da '&'."""
    items = [(k, v) for k, v in params.items() if k != "signature"]
    items.sort(key=lambda x: x[0])
    return "&".join([f"{k}={v}" for k, v in items])

def verify_app_proxy_request(full_url: str, shared_secret: str) -> bool:
    """
    Verifica HMAC dell'App Proxy.
    Shopify aggiunge 'signature' in query. Si calcola HMAC-SHA256 sulla stringa
    dei parametri ordinati (senza 'signature').
    Nota: per l'App Proxy la verifica canonica usa i params; non l'HMAC HTTP header.
    """
    if not shared_secret:
        return False
    parsed = urlparse(full_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    provided = params.get("signature", "")
    msg = sort_params_for_signature(params).encode("utf-8")
    digest = hmac.new(shared_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, provided)

async def add_customer_tag(customer_id_numeric: str, tag: str) -> Dict[str, Any]:
    """
    Aggiunge (o unisce) un tag al customer via Admin GraphQL.
    Funziona solo se SHOP_DOMAIN e SHOP_ADMIN_TOKEN sono impostati.
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

    url = f"https://{SHOP_DOMAIN}/admin/api/{API_VER}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, headers=headers, json={"query": query, "variables": variables})
        data = r.json()
        errs = (data.get("data", {}).get("tagsAdd", {}).get("userErrors") or [])
        return {
            "ok": (r.status_code == 200 and not errs),
            "status": r.status_code,
            "errors": errs,
            "response": data,
        }

def safe_json(obj: Any) -> Any:
    try:
        json.dumps(obj)  # validate
        return obj
    except Exception:
        return str(obj)

# ========= BASE / HEALTH =========
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
    return {"ok": True, "service": "Eccomi Proxy", "verify_hmac": VERIFY_APP_PROXY_HMAC}

# ========= PROXY ROOT (mappa /apps/eccomi) =========
@app.get("/proxy")
async def proxy_root():
    return {
        "ok": True,
        "service": "Eccomi Proxy",
        "hint": "mapping OK (Shopify → /apps/eccomi)",
    }

# ========= ENDPOINT CAPTURE (alias diretto) =========
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer_alias(req: Request):
    """
    Alias 'diretto' (senza App Proxy). Utile per test e per chiamate server-to-server.
    """
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    qp = dict(req.query_params)

    # logica minima: se arriva customer_id o email, prova ad aggiungere un tag
    customer_id = str(qp.get("cid") or payload.get("customer_id") or "")
    email = qp.get("email") or payload.get("email")
    tag = qp.get("tag") or DEFAULT_TAG

    tag_res = {}
    if customer_id:
        tag_res = await add_customer_tag(customer_id, tag)

    return JSONResponse({
        "ok": True,
        "via": "direct",
        "received": {"query": qp, "json": safe_json(payload)},
        "actions": {"tag_customer": tag_res},
        "email": email
    })

# ========= ENDPOINT CAPTURE via APP PROXY =========
@app.api_route("/proxy/capture-customer", methods=["GET", "POST"])
async def capture_customer_proxy(req: Request):
    """
    Versione proxata da Shopify: /apps/eccomi/capture-customer?cid=...&email=...
    Se VERIFY_APP_PROXY_HMAC=true, verifica la firma 'signature' della query.
    """
    # HMAC opzionale (consigliato attivarlo quando è tutto ok)
    if VERIFY_APP_PROXY_HMAC:
        full_url = str(req.url)
        if not verify_app_proxy_request(full_url, APP_SHARED_SECRET):
            raise HTTPException(status_code=403, detail="Invalid app proxy signature")

    try:
        payload = await req.json()
    except Exception:
        payload = {}

    qp = dict(req.query_params)
    customer_id = str(qp.get("cid") or payload.get("customer_id") or "")
    email = qp.get("email") or payload.get("email")
    tag = qp.get("tag") or DEFAULT_TAG

    tag_res = {}
    if customer_id:
        tag_res = await add_customer_tag(customer_id, tag)

    return JSONResponse({
        "ok": True,
        "via": "app-proxy",
        "received": {"query": qp, "json": safe_json(payload)},
        "actions": {"tag_customer": tag_res},
        "email": email
    })

# ========= AVVIO LOCALE =========
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
