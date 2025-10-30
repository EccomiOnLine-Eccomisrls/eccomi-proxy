# ============================================================
# main.py — Eccomi Proxy v1.7 (completo e robusto)
# ============================================================
# - App Proxy: /proxy, /proxy/capture-customer
# - Alias diretto: /capture-customer (per test locali, NON dal frontend)
# - Fallback customer id: logged_in_customer_id
# - HMAC App Proxy opzionale (firma Shopify) — doppia modalità compatibile
# - Aggiunta tag cliente (multipli) via Admin GraphQL
# - Endpoint diagnostici: /health, /hmac-check
# ============================================================

import os, hmac, hashlib, json, httpx
from urllib.parse import urlparse, parse_qsl
from typing import Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# ENV / CONFIG
# ============================================================
PORT = int(os.getenv("PORT", "10000"))

# Sicurezza App Proxy
APP_SHARED_SECRET = os.getenv("SHOPIFY_APP_SHARED_SECRET", "")
VERIFY_APP_PROXY_HMAC = os.getenv("VERIFY_APP_PROXY_HMAC", "true").lower() == "true"

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
app = FastAPI(title="Eccomi Proxy", version="1.7.0")

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

def _hex_hmac(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_app_proxy_request(full_url: str, shared_secret: str) -> Dict[str, Any]:
    """
    Verifica HMAC App Proxy (Shopify).
    Alcuni setup calcolano la firma su:
      A) canonical = 'k=v&k2=v2' (ordinati, senza 'signature')
      B) path + '?' + canonical
    Accettiamo se combacia A o B (maggiore compatibilità).
    """
    if not shared_secret:
        return {"ok": False, "mode": None}

    parsed = urlparse(full_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    provided = params.pop("signature", None)
    if not provided:
        return {"ok": False, "mode": None}

    canonical = _sorted_qs_without_signature(params)

    # Modalità A: solo canonical
    comp_a = _hex_hmac(shared_secret, canonical)

    # Modalità B: path + '?' + canonical (solo se canonical presente)
    msg_b = f"{parsed.path}?{canonical}" if canonical else parsed.path
    comp_b = _hex_hmac(shared_secret, msg_b)

    if hmac.compare_digest(comp_a, provided):
        return {"ok": True, "mode": "A"}
    if hmac.compare_digest(comp_b, provided):
        return {"ok": True, "mode": "B"}

    return {"ok": False, "mode": None}

def require_hmac(req: Request):
    if not VERIFY_APP_PROXY_HMAC:
        return {"skipped": True}
    if not APP_SHARED_SECRET:
        raise HTTPException(500, "Missing SHOPIFY_APP_SHARED_SECRET")
    vr = verify_app_proxy_request(str(req.url), APP_SHARED_SECRET)
    if not vr.get("ok"):
        raise HTTPException(403, "Invalid app proxy signature")
    return vr

async def add_customer_tags(customer_id_numeric: str, tags: List[str]) -> Dict[str, Any]:
    """
    Aggiunge uno o più tag al customer via Admin GraphQL.
    """
    if not (SHOP_DOMAIN and SHOP_ADMIN_TOKEN and customer_id_numeric):
        return {"ok": False, "skipped": "missing_admin_env_or_id"}

    gid = f"gid://shopify/Customer/{customer_id_numeric}"
    query = """
    mutation tagsAdd($id: ID!, $tags: [String!]!) {
      tagsAdd(id: $id, tags: $tags) { userErrors { field message } }
    }
    """
    variables = {"id": gid, "tags": tags}
    url = f"https://{SHOP_DOMAIN}/admin/api/{SHOPIFY_API_VER}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOP_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    try:
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
    except Exception as e:
        return {"ok": False, "network_error": str(e)}

def extract_customer_id(qp: Dict[str, str], payload: Dict[str, Any]) -> str:
    raw = (qp.get("cid") or payload.get("customer_id") or qp.get("logged_in_customer_id") or "").strip()
    raw = "".join(ch for ch in raw if ch.isdigit())
    return raw if raw else ""

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
        "version": "1.7.0",
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
    hmac_info = None
    if via == "app-proxy":
        res = require_hmac(req)
        hmac_info = res if isinstance(res, dict) else None

    customer_id = extract_customer_id(qp, payload)
    email = qp.get("email") or payload.get("email")

    # Supporta più tag separati da virgola o parametro "tags"
    raw_tags = qp.get("tags") or qp.get("tag") or DEFAULT_CAPTURE_TAG
    tags = [t.strip() for t in str(raw_tags).split(",") if t.strip()]

    tag_result = {}
    if customer_id:
        tag_result = await add_customer_tags(customer_id, tags)

    response: Dict[str, Any] = {
        "ok": True,
        "via": via,
        "customer_id": customer_id or None,
        "email": email or None,
        "actions": {"tagsAdd": tag_result},
    }

    if DEBUG_ECHO:
        response["received"] = {"query": _safe_jsonable(qp), "json": _safe_jsonable(payload)}
        response["meta"] = base_meta(qp)
        if hmac_info:
            response["hmac"] = {"checked": True, "mode": hmac_info.get("mode")}

    return JSONResponse(response)

# ============================================================
# ROUTES CAPTURE
# ============================================================
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer_direct(req: Request):
    # alias diretto (non passa dal proxy, utile solo per test locali/Render)
    return await handle_capture(req, via="direct")

@app.api_route("/proxy/capture-customer", methods=["GET", "POST"])
async def capture_customer_proxy(req: Request):
    # rotta chiamata dal proxy: /apps/eccomi-proxy/capture-customer → /proxy/capture-customer
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

    vr = verify_app_proxy_request(str(req.url), APP_SHARED_SECRET)
    return JSONResponse({
        "ok": bool(vr.get("ok")),
        "mode": vr.get("mode"),
        "verify_hmac_flag": True,
        "meta": base_meta(dict(req.query_params)),
        "hint": "firma App Proxy valida" if vr.get("ok") else "firma mancante/non valida"
    })

# ============================================================
# MAIN (locale)
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
