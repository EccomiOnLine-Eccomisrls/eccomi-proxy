from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Eccomi Proxy Running ✅"}

@app.get("/capture-customer")
async def capture_customer(request: Request):
    # Intestazione richiesta da Shopify App Proxy
    embedded = request.headers.get("X-Shopify-Proxy-Request", "NO")
    return {
        "ok": True,
        "msg": "Eccomi Proxy READY ✅",
        "proxied": embedded  # Deve diventare "1" quando passa da Shopify
    }
