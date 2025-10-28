import os, json, requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

SHOP_DOMAIN = os.getenv("SHOP_DOMAIN", "")            # es: eccomionline.myshopify.com
ADMIN_TOKEN = os.getenv("SHOP_ADMIN_TOKEN", "")       # Admin API access token
API_V = os.getenv("SHOP_API_VERSION", "2024-07")

app = FastAPI(title="Eccomi Proxy", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

def _headers():
    return {"X-Shopify-Access-Token": ADMIN_TOKEN, "Content-Type": "application/json"}

def _s(o): return json.dumps(o, separators=(",", ":"), ensure_ascii=False)

def find_customer_by_email(email: str):
    if not email: return None
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/customers/search.json?query=email:{email}"
    r = requests.get(url, headers=_headers(), timeout=15); r.raise_for_status()
    customers = r.json().get("customers", [])
    return customers[0] if customers else None

def update_note(cid: int, payload: dict):
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/customers/{cid}.json"
    body = {"customer": {"id": cid, "note": _s(payload)}}
    r = requests.put(url, headers=_headers(), data=json.dumps(body), timeout=15); r.raise_for_status()

def list_metafields(cid: int):
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/customers/{cid}/metafields.json"
    r = requests.get(url, headers=_headers(), timeout=15); r.raise_for_status()
    return r.json().get("metafields", [])

def upsert_metafield(cid: int, ns: str, key: str, value, typ: str):
    existing = next((m for m in list_metafields(cid) if m.get("namespace")==ns and m.get("key")==key), None)
    if existing:
        mid = existing["id"]
        url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/metafields/{mid}.json"
        body = {"metafield": {"id": mid, "value": value, "type": typ}}
        r = requests.put(url, headers=_headers(), data=json.dumps(body), timeout=15); r.raise_for_status(); return
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/metafields.json"
    body = {"metafield": {
        "namespace": ns, "key": key, "value": value, "type": typ,
        "owner_resource": "customer", "owner_id": cid
    }}
    r = requests.post(url, headers=_headers(), data=json.dumps(body), timeout=15); r.raise_for_status()

def merge_tags(cid: int, new_tags: list[str]):
    url = f"https://{SHOP_DOMAIN}/admin/api/{API_V}/customers/{cid}.json"
    r = requests.get(url, headers=_headers(), timeout=15); r.raise_for_status()
    cur = [t.strip() for t in (r.json()["customer"].get("tags","") or "").split(",") if t.strip()]
    merged = sorted(set(cur + new_tags))
    body = {"customer": {"id": cid, "tags": ", ".join(merged)}}
    rr = requests.put(url, headers=_headers(), data=json.dumps(body), timeout=15); rr.raise_for_status()

@app.get("/")
def root(): return {"service":"Eccomi Proxy","health":"/health","capture":"/capture-customer"}

@app.get("/health")
def health(): return {"ok": bool(SHOP_DOMAIN and ADMIN_TOKEN), "domain": SHOP_DOMAIN}

@app.post("/capture-customer")
async def capture_customer(req: Request):
    p = await req.json()
    email = (p.get("email_login") or p.get("email2") or "").strip().lower()
    if not email: return {"ok": False, "reason": "email_login mancante"}

    cust = find_customer_by_email(email)
    if not cust: return {"ok": False, "reason": "cliente non trovato", "email": email}
    cid = cust["id"]

    # NOTE
    update_note(cid, p)

    # METAFIELDS
    addr = p.get("address") or {}
    cons = p.get("consensi") or {}
    fields = [
        ("eccomi","account_type", p.get("account_type",""), "single_line_text_field"),
        ("eccomi","cf", p.get("cf") or "", "single_line_text_field"),
        ("eccomi","piva", p.get("piva") or "", "single_line_text_field"),
        ("eccomi","sdi", p.get("sdi") or "", "single_line_text_field"),
        ("eccomi","pec", p.get("pec") or "", "single_line_text_field"),
        ("eccomi","addr_street", addr.get("street",""), "single_line_text_field"),
        ("eccomi","addr_cap", addr.get("cap",""), "single_line_text_field"),
        ("eccomi","addr_city", addr.get("city",""), "single_line_text_field"),
        ("eccomi","addr_prov", addr.get("prov",""), "single_line_text_field"),
        ("eccomi","addr_country", addr.get("country","IT"), "single_line_text_field"),
        ("eccomi","phone", p.get("phone") or "", "single_line_text_field"),
        ("eccomi","terms_version", p.get("terms_version",""), "single_line_text_field"),
        ("eccomi","ts_client", p.get("ts_client",""), "single_line_text_field"),
        ("eccomi","consensi", json.dumps(cons, separators=(",", ":")), "json"),
    ]
    for ns,key,val,typ in fields:
        try: upsert_metafield(cid, ns, key, val, typ)
        except Exception as e: print("metafield error", key, e)

    # TAGS
    t = p.get("account_type","privato")
    promo = (cons.get("promo") is True)
    tags = [f"EC_TYPE:{t}", "TERMS:v1.0-2025", f"CONS_PROMO:{'true' if promo else 'false'}", "PROFILE:ok"]
    try: merge_tags(cid, tags)
    except Exception as e: print("tag error", e)

    return {"ok": True, "customer_id": cid}
