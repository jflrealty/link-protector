from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx, os

app = FastAPI()

# Usa envvar pra secret key
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "fallback-secret"))

# Variáveis de ambiente
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")
ALLOWED_DOMAIN = os.getenv("ALLOWED_DOMAIN")
BI_REDIRECT_URL = os.getenv("BI_REDIRECT_URL")

# URLs da Microsoft
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/User.Read"

@app.get("/")
async def protected_home(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(
            f"{AUTH_URL}?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&response_mode=query&scope={SCOPE}&state=123"
        )
    
    email = user.get("mail") or user.get("userPrincipalName")
    if email.endswith(f"@{ALLOWED_DOMAIN}"):
        return RedirectResponse(BI_REDIRECT_URL)
    return HTMLResponse("<h3>Acesso negado: domínio não autorizado.</h3>", status_code=403)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str):
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(TOKEN_URL, data={
            "client_id": CLIENT_ID,
            "scope": SCOPE,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
            "client_secret": CLIENT_SECRET
        })
        token_data = token_resp.json()
        access_token = token_data.get("access_token")

        headers = {"Authorization": f"Bearer {access_token}"}
        user_resp = await client.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        user_data = user_resp.json()

    request.session["user"] = user_data
    return RedirectResponse("/")
