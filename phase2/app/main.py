from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import os
import base64
import time
import hmac
import hashlib
import struct
import qrcode
from io import BytesIO
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.options_to_json import options_to_json
import json
from fastapi import HTTPException

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# 暫時用 dict 當資料庫
users = {}

RP_ID = "localhost"
RP_NAME = "Cryptography Engineering Project"
EXPECTED_ORIGIN = "http://localhost:8000"

registration_challenges = {}
authentication_challenges = {}

def generate_secret():
    # 產生 base32 secret，給 Google Authenticator 使用
    return base64.b32encode(os.urandom(10)).decode("utf-8")


def generate_totp(secret, time_step=None):
    if time_step is None:
        time_step = int(time.time() // 30)

    # base32 decode
    key = base64.b32decode(secret, casefold=True)

    # 將 time_step 打包成 8-byte big-endian
    msg = struct.pack(">Q", time_step)

    # HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic truncation
    offset = h[-1] & 0x0F
    binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF

    # 取 6 位數
    otp = binary % 1000000
    return str(otp).zfill(6)


def verify_totp(secret, user_code):
    current_step = int(time.time() // 30)

    # 容忍前後各一個 time step
    for step in [current_step - 1, current_step, current_step + 1]:
        if generate_totp(secret, step) == user_code:
            return True

    return False


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>Phase 2 Home</h1>
    <a href="/register">Register</a><br>
    <a href="/login">Login</a>
    """


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request}
    )


@app.post("/register", response_class=HTMLResponse)
def register(username: str = Form(...), password: str = Form(...)):
    if username in users:
        return """
        <h2>Register failed: username already exists</h2>
        <a href="/register">Back</a>
        """

    secret = generate_secret()

    users[username] = {
        "password": password,
        "secret": secret
    }

    current_code = generate_totp(secret)

    # Google Authenticator 用的 otpauth URL
    otp_url = f"otpauth://totp/MyApp:{username}?secret={secret}&issuer=MyApp"

    # 產生 QR code
    qr = qrcode.make(otp_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return f"""
    <h2>Register success</h2>
    <p>Username: {username}</p>
    <p>Your secret key: <b>{secret}</b></p>

    <p>Scan this QR code with Google Authenticator:</p>
    <img src="data:image/png;base64,{img_str}" alt="QR Code">

    <p>Current TOTP code (for testing): <b>{current_code}</b></p>
    <p>Please save this secret key. You will use it to generate your 6-digit code.</p>
    <a href="/login">Go to Login</a>
    """


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    if username not in users:
        return """
        <h2>Login failed: user not found</h2>
        <a href="/login">Back</a>
        """

    if users[username]["password"] != password:
        return """
        <h2>Login failed: wrong password</h2>
        <a href="/login">Back</a>
        """

    return f"""
    <h2>Password correct</h2>
    <p>Welcome, {username}</p>
    <p>Please enter your 6-digit TOTP code.</p>

    <form action="/verify" method="post">
        <input type="hidden" name="username" value="{username}">
        <label>6-digit code:</label>
        <input type="text" name="code" maxlength="6" required>
        <br><br>
        <button type="submit">Verify</button>
    </form>
    """


@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request):
    return templates.TemplateResponse(
        "verify.html",
        {"request": request}
    )


@app.post("/verify", response_class=HTMLResponse)
def verify(username: str = Form(...), code: str = Form(...)):
    if username not in users:
        return """
        <h2>Verification failed: user not found</h2>
        <a href="/login">Back to Login</a>
        """

    secret = users[username]["secret"]

    if verify_totp(secret, code):
        return f"""
        <h2>2FA success</h2>
        <p>Welcome, {username}</p>
        <p>You have successfully logged in with password + TOTP.</p>
        """
    else:
        current_code = generate_totp(secret)
        return f"""
        <h2>Verification failed: invalid TOTP code</h2>
        <p>Username: {username}</p>
        <p>Current TOTP code (for testing): <b>{current_code}</b></p>
        <a href="/login">Back to Login</a>
        """

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
        raise HTTPException(status_code=400, detail="Challenge not found for this user. Please request options first.")

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
        raise HTTPException(status_code=400, detail="Challenge not found. Please request login options first.")

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