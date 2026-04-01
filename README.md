# Cryptography Engineering - Project 1

## Environment Setup

We strictly followed the project specifications. No additional packages or setup commands are required. 
Please start the Docker environment using the standard command:

```bash
cd 25_project1
docker compose up --build -d
```

## Execution & Testing Guide
Before testing each phase, please ensure any previously running Uvicorn server in your terminal is stopped by pressing Ctrl + C.

### Phase 1: The "Evil" Login Page (Phishing)
**1. Start the server:**

```bash
docker compose exec app uvicorn phase1.app.main:app --host 0.0.0.0 --port 8000 --reload
```
**2. How to test:**

- Open http://localhost:8000 in your browser.

- You will see a fake Google Sign-in page. Enter any dummy email and password, then click "Next".

- The page will simulate a loading state and then automatically redirect you to the real https://myaccount.google.com/ so the victim won't suspect anything.

- Check phase1/app/passwords.txt in the project directory. The stolen credentials will be recorded there in plain text.

### Phase 2: Symmetric 2FA (TOTP)
**1. Start the server:**

```bash
docker compose exec app uvicorn phase2.app.main:app --host 0.0.0.0 --port 8000 --reload
```
**2. How to test:**

- Register: Go to http://localhost:8000/register. Register a new account. The system will display your Secret Key, a QR code for Google Authenticator, and the current 6-digit TOTP code for testing.

- Login: Go to http://localhost:8000/login. Enter your username and password.

- Verify: Enter the 6-digit TOTP code to successfully log in. (The system allows a ±30-second window for verification).

### Phase 3: Asymmetric 2FA (WebAuthn / Passkey)
**1. Start the server:**

```bash
docker compose exec app uvicorn phase3.app.main:app --host 0.0.0.0 --port 8000 --reload
```
**2. How to test:**

- Register: Go to http://localhost:8000/register. Enter a username and click "Register Passkey" to bind your device's biometric/PIN (e.g., TouchID, Windows Hello).

- Login: Go to http://localhost:8000/login. Enter the same username and click "Login with Passkey" to authenticate via digital signature.

- Note: Phase 3 uses an independent in-memory dictionary. Please register a new user specifically for this phase.
