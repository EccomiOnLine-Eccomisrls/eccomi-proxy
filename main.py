# ============================================================
# main.py — Eccomi Proxy v1.9 PRO
#
# ESISTENTE:
# - /capture-customer
# - /proxy/capture-customer
# - Multi-tag via Admin GraphQL (tagsAdd)
# - /health
# - /hmac-check
#
# NUOVO — FASE 1 ANAGRAFICA FISCALE:
# - /proxy/customer-fiscal-data
# - SOLA LETTURA dei metafield fiscali del cliente loggato
# - Signature App Proxy OBBLIGATORIA sulla nuova rotta
#
# NON scrive dati fiscali.
# NON modifica il carrello.
# ============================================================

import os
import json
import hmac
import hashlib
import httpx

from urllib.parse import urlparse, parse_qsl
from typing import Any, Dict, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# ENV / CONFIG
# ============================================================

PORT = int(os.getenv("PORT", "10000"))

SHOP_DOMAIN = os.getenv(
    "SHOP_DOMAIN",
    "eccomionline.myshopify.com"
)

SHOP_ADMIN_TOKEN = os.getenv(
    "SHOP_ADMIN_TOKEN",
    ""
)

SHOPIFY_API_VER = os.getenv(
    "SHOPIFY_API_VER",
    "2025-10"
)

APP_SHARED_SECRET = os.getenv(
    "SHOPIFY_APP_SHARED_SECRET",
    ""
)

VERIFY_APP_PROXY_HMAC = (
    os.getenv("VERIFY_APP_PROXY_HMAC", "true").lower() == "true"
)

DEFAULT_CAPTURE_TAG = os.getenv(
    "DEFAULT_CAPTURE_TAG",
    "Eccomi-Proxy-Captured"
)

ALLOWED_TAGS = [
    t.strip()
    for t in os.getenv("ALLOWED_TAGS", "").split(",")
    if t.strip()
]

DEBUG_ECHO = (
    os.getenv("DEBUG_ECHO", "true").lower() == "true"
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="Eccomi Proxy",
    version="1.9.0 PRO"
)

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


def _split_tags(raw: Any) -> List[str]:
    tags = [
        t.strip()
        for t in str(raw or "").split(",")
        if t.strip()
    ]

    if ALLOWED_TAGS:
        tags = [
            t for t in tags
            if t in ALLOWED_TAGS
        ]

    return tags or (
        [DEFAULT_CAPTURE_TAG]
        if DEFAULT_CAPTURE_TAG
        else []
    )


def _customer_id_from(
    qp: Dict[str, str],
    payload: Dict[str, Any]
) -> str:

    raw = (
        qp.get("cid")
        or payload.get("customer_id")
        or qp.get("logged_in_customer_id")
        or ""
    ).strip()

    return "".join(
        ch for ch in raw
        if ch.isdigit()
    )


# ============================================================
# VECCHIA VERIFICA — MANTENUTA PER COMPATIBILITÀ
# ============================================================

def verify_app_proxy_request(
    full_url: str,
    shared_secret: str
) -> Dict[str, Any]:

    parsed = urlparse(full_url)

    q = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    )

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

    # Manteniamo il comportamento precedente
    # per NON rompere capture-customer.
    if shop.endswith(SHOP_DOMAIN):
        result["ok"] = True
        result["trusted"] = True
        result["hint"] = "trusted-shop"
    else:
        result["hint"] = "shop_mismatch"

    # Diagnostica HMAC precedente
    if shared_secret and provided:

        params = q.copy()
        params.pop("signature", None)

        canonical = "&".join(
            f"{k}={v}"
            for k, v in sorted(
                params.items(),
                key=lambda kv: kv[0]
            )
        )

        digest = hmac.new(
            shared_secret.encode(),
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(
            digest,
            provided
        ):
            result["mode"] = "canonical"

    return result


def require_hmac_or_trust(req: Request):

    if not VERIFY_APP_PROXY_HMAC:
        return {"skipped": True}

    data = verify_app_proxy_request(
        str(req.url),
        APP_SHARED_SECRET
    )

    if not data.get("ok"):
        raise HTTPException(
            status_code=403,
            detail="Invalid or untrusted App Proxy request"
        )

    return data


# ============================================================
# NUOVA VERIFICA STRICT APP PROXY
# Usata SOLO dalla nuova rotta fiscale.
# ============================================================

def verify_app_proxy_signature_strict(
    req: Request
) -> Dict[str, Any]:

    if not APP_SHARED_SECRET:
        raise HTTPException(
            status_code=500,
            detail="SHOPIFY_APP_SHARED_SECRET not configured"
        )

    # Starlette conserva anche eventuali parametri ripetuti.
    pairs = list(req.query_params.multi_items())

    provided_signature = None
    unsigned_pairs = []

    for key, value in pairs:
        if key == "signature":
            provided_signature = value
        else:
            unsigned_pairs.append((key, value))

    if not provided_signature:
        raise HTTPException(
            status_code=403,
            detail="Missing App Proxy signature"
        )

    # Shopify App Proxy:
    # ordiniamo per chiave e costruiamo la message string
    # senza "&" tra le coppie.
    unsigned_pairs.sort(
        key=lambda item: item[0]
    )

    message = "".join(
        f"{key}={value}"
        for key, value in unsigned_pairs
    )

    calculated_signature = hmac.new(
        APP_SHARED_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(
        calculated_signature,
        provided_signature
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid App Proxy signature"
        )

    shop = req.query_params.get("shop", "")

    if shop != SHOP_DOMAIN:
        raise HTTPException(
            status_code=403,
            detail="Invalid shop"
        )

    return {
        "ok": True,
        "mode": "strict",
        "shop": shop,
        "logged_in_customer_id":
            req.query_params.get(
                "logged_in_customer_id"
            ),
    }


# ============================================================
# ADMIN GRAPHQL — HELPER
# ============================================================

async def shopify_admin_graphql(
    query: str,
    variables: Dict[str, Any]
) -> Dict[str, Any]:

    if not SHOP_DOMAIN:
        raise HTTPException(
            status_code=500,
            detail="SHOP_DOMAIN not configured"
        )

    if not SHOP_ADMIN_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="SHOP_ADMIN_TOKEN not configured"
        )

    url = (
        f"https://{SHOP_DOMAIN}"
        f"/admin/api/{SHOPIFY_API_VER}"
        f"/graphql.json"
    )

    headers = {
        "X-Shopify-Access-Token":
            SHOP_ADMIN_TOKEN,
        "Content-Type":
            "application/json",
    }

    try:

        async with httpx.AsyncClient(
            timeout=30
        ) as client:

            response = await client.post(
                url,
                headers=headers,
                json={
                    "query": query,
                    "variables": variables,
                },
            )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Shopify connection error: {str(exc)}"
        )

    try:
        data = response.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Invalid response from Shopify"
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail={
                "shopify_status":
                    response.status_code,
                "shopify_response":
                    data,
            },
        )

    if data.get("errors"):
        raise HTTPException(
            status_code=502,
            detail={
                "shopify_graphql_errors":
                    data.get("errors")
            },
        )

    return data


# ============================================================
# ADMIN API — TAGS
# CODICE ESISTENTE MANTENUTO
# ============================================================

async def add_customer_tags(
    customer_id_numeric: str,
    tags: List[str]
) -> Dict[str, Any]:

    if not (
        SHOP_DOMAIN
        and SHOP_ADMIN_TOKEN
        and customer_id_numeric
        and tags
    ):
        return {
            "ok": False,
            "skipped":
                "missing_env_or_id_or_tags"
        }

    gid = (
        f"gid://shopify/Customer/"
        f"{customer_id_numeric}"
    )

    query = """
    mutation tagsAdd(
      $id: ID!,
      $tags: [String!]!
    ) {
      tagsAdd(
        id: $id,
        tags: $tags
      ) {
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "id": gid,
        "tags": tags
    }

    url = (
        f"https://{SHOP_DOMAIN}"
        f"/admin/api/{SHOPIFY_API_VER}"
        f"/graphql.json"
    )

    headers = {
        "X-Shopify-Access-Token":
            SHOP_ADMIN_TOKEN,
        "Content-Type":
            "application/json"
    }

    try:

        async with httpx.AsyncClient(
            timeout=30
        ) as client:

            resp = await client.post(
                url,
                headers=headers,
                json={
                    "query": query,
                    "variables": variables
                }
            )

            data = resp.json()

            errs = (
                data.get(
                    "data", {}
                )
                .get(
                    "tagsAdd", {}
                )
                .get(
                    "userErrors"
                )
                or []
            )

            return {
                "ok":
                    (
                        resp.status_code == 200
                        and not errs
                    ),
                "status":
                    resp.status_code,
                "errors":
                    errs,
                "response":
                    data
            }

    except Exception as e:

        return {
            "ok": False,
            "network_error": str(e)
        }


# ============================================================
# NUOVO — LETTURA DATI FISCALI CUSTOMER
# ============================================================

async def get_customer_fiscal_data(
    customer_id_numeric: str
) -> Dict[str, Any]:

    gid = (
        f"gid://shopify/Customer/"
        f"{customer_id_numeric}"
    )

    query = """
    query EccomiCustomerFiscalData($id: ID!) {
      customer(id: $id) {

        id

        tipoCliente: metafield(
          namespace: "eccomi"
          key: "tipo_cliente"
        ) {
          value
        }

        codiceFiscale: metafield(
          namespace: "eccomi"
          key: "codice_fiscale"
        ) {
          value
        }

        partitaIva: metafield(
          namespace: "eccomi"
          key: "partita_iva"
        ) {
          value
        }

        codiceSdi: metafield(
          namespace: "eccomi"
          key: "codice_sdi"
        ) {
          value
        }

        pec: metafield(
          namespace: "eccomi"
          key: "pec"
        ) {
          value
        }
      }
    }
    """

    data = await shopify_admin_graphql(
        query,
        {"id": gid}
    )

    customer = (
        data.get("data", {})
        .get("customer")
    )

    if not customer:
        raise HTTPException(
            status_code=404,
            detail="Customer not found"
        )

    def mf_value(name: str):
        item = customer.get(name)
        if not item:
            return None

        value = item.get("value")

        if value is None:
            return None

        value = str(value).strip()

        return value if value else None

    return {
        "tipo_cliente":
            mf_value("tipoCliente"),

        "codice_fiscale":
            mf_value("codiceFiscale"),

        "partita_iva":
            mf_value("partitaIva"),

        "codice_sdi":
            mf_value("codiceSdi"),

        "pec":
            mf_value("pec"),
    }


# ============================================================
# HANDLER CAPTURE ESISTENTE
# ============================================================

async def handle_capture(req: Request):

    try:
        payload = await req.json()
    except Exception:
        payload = {}

    qp = dict(req.query_params)

    hmac_info = (
        require_hmac_or_trust(req)
        if (
            "signature" in qp
            or VERIFY_APP_PROXY_HMAC
        )
        else {"skipped": True}
    )

    customer_id = _customer_id_from(
        qp,
        payload
    )

    email = (
        qp.get("email")
        or payload.get("email")
    )

    raw_tags = (
        qp.get("tags")
        or qp.get("tag")
        or DEFAULT_CAPTURE_TAG
    )

    tags = _split_tags(raw_tags)

    tag_result = {}

    if customer_id:
        tag_result = await add_customer_tags(
            customer_id,
            tags
        )

    resp = {
        "ok": True,
        "via":
            "app-proxy"
            if "signature" in qp
            else "direct",

        "customer_id":
            customer_id or None,

        "email":
            email or None,

        "actions": {
            "tagsAdd":
                tag_result
        },
    }

    if DEBUG_ECHO:

        resp["received"] = {
            "query":
                _safe_jsonable(qp),
            "json":
                _safe_jsonable(payload)
        }

        resp["hmac"] = hmac_info

    return JSONResponse(resp)


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
async def root():

    return {
        "service":
            "Eccomi Proxy",

        "version":
            "1.9.0 PRO",

        "routes": [
            "/health",
            "/hmac-check",
            "/capture-customer",
            "/proxy/capture-customer",
            "/proxy/customer-fiscal-data",
        ],

        "verify_hmac_enabled":
            VERIFY_APP_PROXY_HMAC,

        "shop":
            SHOP_DOMAIN,
    }


@app.get("/health")
async def health():

    return {
        "ok": True,
        "service": "Eccomi Proxy",
        "version": "1.9.0 PRO",
        "verify_hmac":
            VERIFY_APP_PROXY_HMAC,
        "shop":
            SHOP_DOMAIN
    }


@app.get("/hmac-check")
async def hmac_check(req: Request):

    data = verify_app_proxy_request(
        str(req.url),
        APP_SHARED_SECRET
    )

    return JSONResponse(data)


@app.api_route(
    "/capture-customer",
    methods=["GET", "POST"]
)
async def capture_customer_direct(
    req: Request
):

    return await handle_capture(req)


@app.api_route(
    "/proxy/capture-customer",
    methods=["GET", "POST"]
)
async def capture_customer_proxy(
    req: Request
):

    return await handle_capture(req)


# ============================================================
# NUOVA ROTTA — FASE 1
# SOLO LETTURA
# ============================================================

@app.get(
    "/proxy/customer-fiscal-data"
)
async def customer_fiscal_data(
    req: Request
):

    # Per questa rotta NON usiamo SafeMode.
    # La signature Shopify deve essere valida.
    verify_app_proxy_signature_strict(req)

    customer_id = (
        req.query_params.get(
            "logged_in_customer_id"
        )
        or ""
    ).strip()

    customer_id = "".join(
        ch for ch in customer_id
        if ch.isdigit()
    )

    # Cliente non autenticato:
    # non è un errore applicativo.
    if not customer_id:

        return JSONResponse({
            "ok": True,
            "logged_in": False,
            "fiscal_data": None
        })

    fiscal_data = (
        await get_customer_fiscal_data(
            customer_id
        )
    )

    return JSONResponse({
        "ok": True,
        "logged_in": True,
        "fiscal_data": fiscal_data
    })
    
# ============================================================
# ALIAS PUBBLICO APP PROXY
# Shopify:
# /apps/eccomi-proxy/customer-fiscal-data
# -> Render:
# /customer-fiscal-data
# ============================================================

@app.get("/customer-fiscal-data")
async def customer_fiscal_data_public(req: Request):
    return await customer_fiscal_data(req)

# ============================================================
# MAIN LOCAL
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT
    )
