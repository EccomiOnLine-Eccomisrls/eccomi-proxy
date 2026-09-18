# ============================================================
# main.py — Eccomi Proxy v2.0 PRO
#
# ESISTENTE:
# - /capture-customer
# - /proxy/capture-customer
# - Multi-tag via Admin GraphQL (tagsAdd)
# - /health
# - /hmac-check
#
# ANAGRAFICA FISCALE CUSTOMER:
# - GET  /proxy/customer-fiscal-data
# - POST /proxy/customer-fiscal-data
# - GET  /customer-fiscal-data
# - POST /customer-fiscal-data
#
# GET:
# - legge i metafield fiscali del cliente loggato
#
# POST:
# - salva/aggiorna i metafield fiscali del cliente loggato
#
# SICUREZZA:
# - Signature Shopify App Proxy obbligatoria
# - customer_id preso SOLO da logged_in_customer_id firmato
#
# NON modifica il carrello.
# NON modifica il checkout.
# NON modifica gli attributi ordine già esistenti.
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
    version="2.0.0 PRO"
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
            t
            for t in tags
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
        ch
        for ch in raw
        if ch.isdigit()
    )


def _clean_string(
    value: Any,
    uppercase: bool = False
):

    if value is None:
        return None

    value = str(value).strip()

    if uppercase:
        value = value.upper()

    return value if value else None


# ============================================================
# VECCHIA VERIFICA
# MANTENUTA PER COMPATIBILITÀ CON capture-customer
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

    # Manteniamo questo comportamento esclusivamente
    # per non rompere il vecchio capture-customer.
    if shop.endswith(SHOP_DOMAIN):
        result["ok"] = True
        result["trusted"] = True
        result["hint"] = "trusted-shop"
    else:
        result["hint"] = "shop_mismatch"

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


def require_hmac_or_trust(
    req: Request
):

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
# STRICT SHOPIFY APP PROXY SIGNATURE
# USATA PER L'ANAGRAFICA FISCALE
# ============================================================

def verify_app_proxy_signature_strict(
    req: Request
) -> Dict[str, Any]:

    if not APP_SHARED_SECRET:
        raise HTTPException(
            status_code=500,
            detail="SHOPIFY_APP_SHARED_SECRET not configured"
        )

    # Raggruppiamo i parametri per chiave.
    # Shopify può inviare parametri ripetuti.
    grouped: Dict[str, List[str]] = {}
    provided_signature = None

    for key, value in req.query_params.multi_items():

        if key == "signature":
            provided_signature = value
            continue

        grouped.setdefault(
            key,
            []
        ).append(value)

    if not provided_signature:
        raise HTTPException(
            status_code=403,
            detail="Missing App Proxy signature"
        )

    # Shopify App Proxy:
    # key=value1,value2
    # ordinati per chiave
    # concatenati senza "&".
    message_parts = []

    for key in sorted(grouped.keys()):

        joined_value = ",".join(
            grouped[key]
        )

        message_parts.append(
            f"{key}={joined_value}"
        )

    message = "".join(
        message_parts
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

    shop = req.query_params.get(
        "shop",
        ""
    )

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
            detail=(
                "Shopify connection error: "
                f"{str(exc)}"
            )
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

    try:

        data = await shopify_admin_graphql(
            query,
            variables
        )

        errs = (
            data.get("data", {})
            .get("tagsAdd", {})
            .get("userErrors")
            or []
        )

        return {
            "ok": not errs,
            "errors": errs,
            "response": data
        }

    except Exception as exc:

        return {
            "ok": False,
            "network_error": str(exc)
        }


# ============================================================
# LETTURA DATI FISCALI CUSTOMER
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
        {
            "id": gid
        }
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

    def mf_value(
        name: str
    ):

        item = customer.get(name)

        if not item:
            return None

        value = item.get("value")

        if value is None:
            return None

        value = str(value).strip()

        return (
            value
            if value
            else None
        )

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
# FASE 2A — SCRITTURA DATI FISCALI CUSTOMER
# ============================================================

async def set_customer_fiscal_data(
    customer_id_numeric: str,
    fiscal_data: Dict[str, Any]
) -> Dict[str, Any]:

    gid = (
        f"gid://shopify/Customer/"
        f"{customer_id_numeric}"
    )

    metafields = []

    field_map = {
        "tipo_cliente":
            "tipo_cliente",

        "codice_fiscale":
            "codice_fiscale",

        "partita_iva":
            "partita_iva",

        "codice_sdi":
            "codice_sdi",

        "pec":
            "pec",
    }

    for input_key, metafield_key in field_map.items():

        # Se il campo NON è presente nel JSON,
        # NON tocchiamo il valore già salvato.
        if input_key not in fiscal_data:
            continue

        value = fiscal_data.get(
            input_key
        )

        # Normalizzazione.
        if input_key in (
            "tipo_cliente",
            "codice_fiscale",
            "codice_sdi"
        ):
            value = _clean_string(
                value,
                uppercase=True
            )

        else:
            value = _clean_string(
                value
            )

        # In FASE 2A non cancelliamo metafield
        # tramite stringhe vuote.
        # Salviamo solo valori effettivamente presenti.
        if value is None:
            continue

        metafields.append({
            "ownerId": gid,
            "namespace": "eccomi",
            "key": metafield_key,
            "type": "single_line_text_field",
            "value": value,
        })

    if not metafields:

        raise HTTPException(
            status_code=400,
            detail="No fiscal data supplied"
        )

    mutation = """
    mutation EccomiSetCustomerFiscalData(
      $metafields: [MetafieldsSetInput!]!
    ) {

      metafieldsSet(
        metafields: $metafields
      ) {

        metafields {
          id
          namespace
          key
          value
          type
        }

        userErrors {
          field
          message
          code
        }
      }
    }
    """

    data = await shopify_admin_graphql(
        mutation,
        {
            "metafields":
                metafields
        }
    )

    result = (
        data.get("data", {})
        .get("metafieldsSet", {})
    )

    errors = (
        result.get("userErrors")
        or []
    )

    if errors:

        raise HTTPException(
            status_code=422,
            detail={
                "message":
                    "Unable to save fiscal data",

                "errors":
                    errors
            }
        )

    return {
        "ok": True,
        "metafields":
            result.get("metafields")
            or []
    }


# ============================================================
# VALIDAZIONE PAYLOAD FISCALE
# ============================================================

def validate_fiscal_payload(
    payload: Dict[str, Any]
) -> Dict[str, Any]:

    allowed_fields = {
        "tipo_cliente",
        "codice_fiscale",
        "partita_iva",
        "codice_sdi",
        "pec",
    }

    cleaned = {}

    for key in allowed_fields:

        if key in payload:
            cleaned[key] = payload.get(key)

    if not cleaned:

        raise HTTPException(
            status_code=400,
            detail="No valid fiscal fields supplied"
        )

    # Tipo cliente
    if "tipo_cliente" in cleaned:

        tipo = _clean_string(
            cleaned.get("tipo_cliente")
        )

        if tipo:

            tipo_lower = tipo.lower()

            if tipo_lower not in (
                "privato",
                "azienda"
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "tipo_cliente must be "
                        "'Privato' or 'Azienda'"
                    )
                )

            cleaned["tipo_cliente"] = (
                "Privato"
                if tipo_lower == "privato"
                else "Azienda"
            )

    # Codice fiscale:
    # validazione formale di 16 caratteri alfanumerici.
    if "codice_fiscale" in cleaned:

        cf = _clean_string(
            cleaned.get("codice_fiscale"),
            uppercase=True
        )

        if cf:

            if (
                len(cf) != 16
                or not cf.isalnum()
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Codice Fiscale non valido: "
                        "sono richiesti 16 caratteri "
                        "alfanumerici"
                    )
                )

            cleaned["codice_fiscale"] = cf

    # Partita IVA:
    # validazione formale di 11 cifre.
    if "partita_iva" in cleaned:

        piva = _clean_string(
            cleaned.get("partita_iva")
        )

        if piva:

            if (
                len(piva) != 11
                or not piva.isdigit()
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Partita IVA non valida: "
                        "sono richieste 11 cifre"
                    )
                )

            cleaned["partita_iva"] = piva

    # SDI
    if "codice_sdi" in cleaned:

        sdi = _clean_string(
            cleaned.get("codice_sdi"),
            uppercase=True
        )

        if sdi:

            if len(sdi) > 7:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Codice SDI non valido"
                    )
                )

            cleaned["codice_sdi"] = sdi

    # PEC
    if "pec" in cleaned:

        pec = _clean_string(
            cleaned.get("pec")
        )

        if pec:

            if (
                "@" not in pec
                or "." not in pec.split("@")[-1]
            ):
                raise HTTPException(
                    status_code=400,
                    detail="PEC non valida"
                )

            cleaned["pec"] = pec.lower()

    return cleaned


# ============================================================
# HANDLER CAPTURE ESISTENTE
# ============================================================

async def handle_capture(
    req: Request
):

    try:
        payload = await req.json()

    except Exception:
        payload = {}

    qp = dict(
        req.query_params
    )

    hmac_info = (
        require_hmac_or_trust(req)
        if (
            "signature" in qp
            or VERIFY_APP_PROXY_HMAC
        )
        else {
            "skipped": True
        }
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

    tags = _split_tags(
        raw_tags
    )

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

        resp["hmac"] = (
            hmac_info
        )

    return JSONResponse(
        resp
    )


# ============================================================
# CUSTOMER ID AUTENTICATO DA APP PROXY
# ============================================================

def get_logged_customer_id(
    req: Request
) -> str:

    raw = (
        req.query_params.get(
            "logged_in_customer_id"
        )
        or ""
    ).strip()

    return "".join(
        ch
        for ch in raw
        if ch.isdigit()
    )


# ============================================================
# HANDLER GET DATI FISCALI
# ============================================================

async def handle_customer_fiscal_get(
    req: Request
):

    verify_app_proxy_signature_strict(
        req
    )

    customer_id = (
        get_logged_customer_id(
            req
        )
    )

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
        "fiscal_data":
            fiscal_data
    })


# ============================================================
# HANDLER POST DATI FISCALI
# ============================================================

async def handle_customer_fiscal_post(
    req: Request
):

    # PRIMA verifichiamo la firma Shopify.
    verify_app_proxy_signature_strict(
        req
    )

    # L'ID cliente NON viene accettato dal body.
    # Usiamo esclusivamente quello firmato da Shopify.
    customer_id = (
        get_logged_customer_id(
            req
        )
    )

    if not customer_id:

        raise HTTPException(
            status_code=401,
            detail="Customer not logged in"
        )

    try:
        payload = await req.json()

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON body"
        )

    if not isinstance(
        payload,
        dict
    ):
        raise HTTPException(
            status_code=400,
            detail="JSON body must be an object"
        )

    cleaned_payload = (
        validate_fiscal_payload(
            payload
        )
    )

    write_result = (
        await set_customer_fiscal_data(
            customer_id,
            cleaned_payload
        )
    )

    # Rileggiamo subito Shopify.
    # In questo modo il test ci dice cosa
    # risulta realmente salvato.
    fiscal_data = (
        await get_customer_fiscal_data(
            customer_id
        )
    )

    return JSONResponse({
        "ok": True,
        "logged_in": True,
        "saved": True,
        "write_result":
            write_result,
        "fiscal_data":
            fiscal_data
    })


# ============================================================
# ROUTES GENERALI
# ============================================================

@app.get("/")
async def root():

    return {
        "service":
            "Eccomi Proxy",

        "version":
            "2.0.0 PRO",

        "routes": [
            "/health",
            "/hmac-check",
            "/capture-customer",
            "/proxy/capture-customer",
            "/proxy/customer-fiscal-data",
            "/customer-fiscal-data",
        ],

        "fiscal_data": {
            "GET":
                "read customer fiscal data",

            "POST":
                "write customer fiscal data"
        },

        "verify_hmac_enabled":
            VERIFY_APP_PROXY_HMAC,

        "shop":
            SHOP_DOMAIN,
    }


@app.get("/health")
async def health():

    return {
        "ok": True,
        "service":
            "Eccomi Proxy",

        "version":
            "2.0.0 PRO",

        "verify_hmac":
            VERIFY_APP_PROXY_HMAC,

        "shop":
            SHOP_DOMAIN
    }


@app.get("/hmac-check")
async def hmac_check(
    req: Request
):

    data = verify_app_proxy_request(
        str(req.url),
        APP_SHARED_SECRET
    )

    return JSONResponse(
        data
    )


# ============================================================
# CAPTURE CUSTOMER — ESISTENTE
# ============================================================

@app.api_route(
    "/capture-customer",
    methods=["GET", "POST"]
)
async def capture_customer_direct(
    req: Request
):

    return await handle_capture(
        req
    )


@app.api_route(
    "/proxy/capture-customer",
    methods=["GET", "POST"]
)
async def capture_customer_proxy(
    req: Request
):

    return await handle_capture(
        req
    )


# ============================================================
# ROTTA INTERNA APP PROXY — DATI FISCALI
# ============================================================

@app.get(
    "/proxy/customer-fiscal-data"
)
async def customer_fiscal_data_get(
    req: Request
):

    return await handle_customer_fiscal_get(
        req
    )


@app.post(
    "/proxy/customer-fiscal-data"
)
async def customer_fiscal_data_post(
    req: Request
):

    return await handle_customer_fiscal_post(
        req
    )


# ============================================================
# ALIAS APP PROXY
#
# Shopify storefront:
# /apps/eccomi-proxy/customer-fiscal-data
#
# Render:
# /customer-fiscal-data
# ============================================================

@app.get(
    "/customer-fiscal-data"
)
async def customer_fiscal_data_public_get(
    req: Request
):

    return await handle_customer_fiscal_get(
        req
    )


@app.post(
    "/customer-fiscal-data"
)
async def customer_fiscal_data_public_post(
    req: Request
):

    return await handle_customer_fiscal_post(
        req
    )


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
