# --- aggiungi in cima ---
import os, httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "")
SHOP_ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")
API_VER = "2025-10"  # ok anche 2024-10

app = FastAPI(title="Eccomi Proxy", version="1.2.0")

@app.get("/")
async def root():
    return {"service": "Eccomi Proxy", "health": "/health", "capture": "/capture-customer"}

@app.get("/health")
async def health():
    return {"ok": True}

# --- helper: aggiunge tag al cliente via Admin GraphQL ---
async def add_customer_tag(customer_id_numeric: str, tag: str) -> dict:
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
    return {"ok": r.status_code == 200, "status": r.status_code, "data": data}

# --- endpoint proxy: non deve MAI esplodere ---
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer(request: Request):
    try:
        headers = {k.lower(): v for k, v in request.headers.items()}
        proxied = headers.get("x-shopify-proxy-request", "NO")  # "1" se passa via App Proxy
        qs = dict(request.query_params)

        # prendiamo id/email dal nostro client (cid/email) oppure dal param Shopify
        cid = qs.get("cid") or qs.get("logged_in_customer_id")
        email = qs.get("email")

        tag_result = None
        # Facoltativo: tagga il cliente solo se:
        # - passaggio via proxy OK
        # - abbiamo l'id cliente
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
        return JSONResponse({"ok": False, "error": str(e)}, status_code=200)
