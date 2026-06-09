import os
import hmac
import hashlib
import asyncio
import json
import time
import jwt
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime, timezone
from pywebpush import WebPusher
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256R1
import base64 as _base64

AUTO_EXPIRE_HOURS = 3


async def auto_expire_task():
    while True:
        await asyncio.sleep(300)  # elke 5 minuten controleren
        now = datetime.now(timezone.utc)
        expired = [
            name for name, since in list(available_users.items())
            if (now - datetime.fromisoformat(since)).total_seconds() > AUTO_EXPIRE_HOURS * 3600
        ]
        for name in expired:
            available_users.pop(name, None)
            await broadcast({"type": "unavailable", "name": name})
            print(f"[AUTO] {name} automatisch afgemeld na {AUTO_EXPIRE_HOURS} uur")


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(auto_expire_task())
    yield


app = FastAPI(lifespan=lifespan)

APP_PASSWORD = os.environ.get("APP_PASSWORD", "belletje")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_SUB = "mailto:app@phone-availability.app"


def _load_vapid_key(b64_key: str):
    try:
        padding = "=" * (4 - len(b64_key) % 4)
        d = int.from_bytes(_base64.urlsafe_b64decode(b64_key + padding), "big")
        return derive_private_key(d, SECP256R1())
    except Exception as e:
        print(f"[PUSH] Sleutel laden mislukt: {e}")
        return None


vapid_private_key = _load_vapid_key(VAPID_PRIVATE_KEY) if VAPID_PRIVATE_KEY else None

available_users: dict[str, str] = {}
connections: list[WebSocket] = []
push_subscriptions: list[dict] = []


def make_token(password: str) -> str:
    return hmac.new(password.encode(), b"phone-availability", hashlib.sha256).hexdigest()


def valid_token(token: str) -> bool:
    expected = make_token(APP_PASSWORD)
    return hmac.compare_digest(token, expected)


class PasswordRequest(BaseModel):
    password: str


class SubscribeRequest(BaseModel):
    token: str
    subscription: dict


@app.post("/verify")
async def verify(req: PasswordRequest):
    if req.password != APP_PASSWORD:
        raise HTTPException(status_code=401, detail="Ongeldig wachtwoord")
    return {"token": make_token(req.password)}


@app.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    if not valid_token(req.token):
        raise HTTPException(status_code=401)
    for existing in push_subscriptions:
        if existing.get("endpoint") == req.subscription.get("endpoint"):
            push_subscriptions.remove(existing)
            break
    push_subscriptions.append(req.subscription)
    print(f"[PUSH] Subscription geregistreerd. Totaal: {len(push_subscriptions)}")
    return {"ok": True}


def _make_vapid_jwt(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    aud = f"{parsed.scheme}://{parsed.netloc}"
    claims = {
        "aud": aud,
        "exp": int(time.time()) + 43200,
        "sub": VAPID_SUB,
    }
    return jwt.encode(claims, vapid_private_key, algorithm="ES256")


def _send_push_sync(sub: dict, data: str) -> int:
    wp = WebPusher(subscription_info=sub)
    token = _make_vapid_jwt(sub["endpoint"])
    resp = wp.send(
        data,
        headers={
            "Authorization": f"vapid t={token},k={VAPID_PUBLIC_KEY}",
            "Urgency": "high",
        },
        ttl=60,
    )
    return resp.status_code


async def send_push(title: str, body: str, skip_endpoint: str = None):
    if not vapid_private_key:
        print("[PUSH] Geen VAPID sleutel ingesteld")
        return
    print(f"[PUSH] Versturen naar {len(push_subscriptions)} apparaten...")
    data = json.dumps({"title": title, "body": body})
    for sub in push_subscriptions[:]:
        if skip_endpoint and sub.get("endpoint") == skip_endpoint:
            continue
        try:
            status = await asyncio.to_thread(_send_push_sync, sub, data)
            if status in (200, 201, 202, 204):
                print("[PUSH] Succesvol verstuurd")
            elif status in (404, 410):
                push_subscriptions.remove(sub)
                print(f"[PUSH] Subscription verlopen, verwijderd ({status})")
            else:
                print(f"[PUSH] Fout: HTTP {status}")
        except Exception as e:
            print(f"[PUSH] Onverwachte fout: {e}")


async def broadcast(message: dict):
    data = json.dumps(message)
    disconnected = []
    for ws in connections:
        try:
            await ws.send_text(data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        connections.remove(ws)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    if not valid_token(token):
        await websocket.accept()
        await websocket.close(code=4001)
        return

    await websocket.accept()
    connections.append(websocket)

    await websocket.send_text(json.dumps({
        "type": "state",
        "users": available_users,
    }))

    try:
        async for raw in websocket.iter_text():
            msg = json.loads(raw)
            name = msg.get("name", "").strip()
            if not name:
                continue

            if msg["type"] == "available":
                available_users[name] = datetime.now(timezone.utc).isoformat()
                await broadcast({"type": "available", "name": name, "since": available_users[name]})
                asyncio.create_task(send_push(
                    f"📞 {name} is beschikbaar!",
                    f"{name} is nu beschikbaar voor een belletje.",
                    skip_endpoint=msg.get("pushEndpoint"),
                ))
            elif msg["type"] == "unavailable":
                available_users.pop(name, None)
                await broadcast({"type": "unavailable", "name": name})

    except WebSocketDisconnect:
        connections.remove(websocket)


@app.get("/sw.js")
async def service_worker():
    return FileResponse("static/sw.js", media_type="application/javascript")


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def root():
    return FileResponse("static/index.html")
