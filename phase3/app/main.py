from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import json

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.options_to_json import options_to_json

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# 獨立的記憶體資料庫
users = {}
registration_challenges = {}
authentication_challenges = {}

# WebAuthn 設定
RP_ID = "localhost"
RP_NAME = "Cryptography Engineering Project"
EXPECTED_ORIGIN = "http://localhost:8000"

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>Phase 3: Passkey Home</h1>
    <a href="/register">Register Passkey</a><br>
    <a href="/login">Login with Passkey</a>
    """

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/webauthn/register/options")
async def webauthn_register_options(request: Request):
    data = await request.json()
    username = data.get("username")

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    if username in users and "webauthn_credential_id" in users[username]:
        raise HTTPException(status_code=400, detail="User already registered with WebAuthn")

    try:
        simple_registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=username.encode("utf-8"),
            user_name=username,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating options: {str(e)}")

    registration_challenges[username] = simple_registration_options.challenge
    return json.loads(options_to_json(simple_registration_options))

@app.post("/webauthn/register/verify")
async def webauthn_register_verify(request: Request):
    data = await request.json()
    username = data.get("username")

    if not username or username not in registration_challenges:
        raise HTTPException(status_code=400, detail="Challenge not found for this user.")

    expected_challenge = registration_challenges[username]

    try:
        verification = verify_registration_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {str(e)}")

    if username not in users:
        users[username] = {}

    users[username]["webauthn_credential_id"] = verification.credential_id
    users[username]["webauthn_public_key"] = verification.credential_public_key
    del registration_challenges[username]

    return {"status": "success", "message": "WebAuthn registration complete. Public key saved."}

@app.post("/webauthn/login/options")
async def webauthn_login_options(request: Request):
    data = await request.json()
    username = data.get("username")

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    if username not in users or "webauthn_credential_id" not in users[username]:
        raise HTTPException(status_code=400, detail="User not registered or WebAuthn not set up.")

    try:
        credential_descriptor = PublicKeyCredentialDescriptor(
            id=users[username]["webauthn_credential_id"]
        )
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[credential_descriptor],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating login options: {str(e)}")

    authentication_challenges[username] = options.challenge
    return json.loads(options_to_json(options))

@app.post("/webauthn/login/verify")
async def webauthn_login_verify(request: Request):
    data = await request.json()
    username = data.get("username")

    if not username or username not in authentication_challenges:
        raise HTTPException(status_code=400, detail="Challenge not found.")

    expected_challenge = authentication_challenges[username]
    public_key = users[username]["webauthn_public_key"]

    try:
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
            credential_public_key=public_key,
            credential_current_sign_count=0,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Login verification failed: {str(e)}")

    del authentication_challenges[username]
    return {"status": "success", "message": f"Welcome back, {username}! WebAuthn login successful."}