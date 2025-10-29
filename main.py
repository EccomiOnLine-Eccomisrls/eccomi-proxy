from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Eccomi Proxy", version="1.0.1")

@app.get("/")
async def root():
    return {"service": "Eccomi Proxy", "health": "/health", "capture": "/capture-customer"}

@app.get("/health")
async def health():
    return {"ok": True}

# Accetta sia GET che POST e NON manda mai 500
@app.api_route("/capture-customer", methods=["GET", "POST"])
async def capture_customer(request: Request):
    try:
        headers = {k.lower(): v for k, v in request.headers.items()}
        proxied = headers.get("x-shopify-proxy-request", "NO")  # "1" quando passa dal proxy
        signature = headers.get("x-shopify-proxy-signature")     # firma HMAC del proxy (info)

        # Parametri query che Shopify aggiunge (shop, path_prefix, timestamp, ecc.)
        qs = dict(request.query_params)

        # Risposta SEMPRE 200 (anche se qualcosa va storto)
        return JSONResponse({
            "ok": True,
            "msg": "Eccomi Proxy READY ✅",
            "proxied": "1" if proxied == "1" else "NO",
            "qs": qs,
            "has_signature": bool(signature)
        }, status_code=200)

    except Exception as e:
        # Non far mai esplodere il proxy: logghiamo l’errore nel body ma teniamo 200
        return JSONResponse({
            "ok": False,
            "error": str(e)
        }, status_code=200)
