import os
import re
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from auth_server.database import initialize_database, redeem_code, verify_session


app = FastAPI(title="KURO HELPER Authentication API", docs_url=None, redoc_url=None)
_rate_lock = threading.Lock()
_rate_events = defaultdict(deque)


class RedeemRequest(BaseModel):
    code: str = Field(min_length=16, max_length=64)
    device_id: str = Field(min_length=20, max_length=64)


class VerifyRequest(BaseModel):
    device_id: str = Field(min_length=20, max_length=64)


@app.on_event("startup")
def on_startup():
    initialize_database()


@app.get("/healthz")
def health_check():
    return {"ok": True}


@app.middleware("http")
async def limit_auth_requests(request: Request, call_next):
    if request.url.path not in ("/v1/auth/redeem", "/v1/auth/verify"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _rate_lock:
        events = _rate_events[client_ip]
        while events and now - events[0] > 60:
            events.popleft()
        if len(events) >= 30:
            return fastapi_response_too_many_requests()
        events.append(now)
    return await call_next(request)


def fastapi_response_too_many_requests():
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=429,
        content={"detail": "요청이 너무 많습니다. 잠시 후 다시 시도하세요."},
    )


@app.post("/v1/auth/redeem")
def redeem(request: RedeemRequest):
    code = request.code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9-]{16,64}", code):
        raise HTTPException(status_code=400, detail="인증 코드 형식이 올바르지 않습니다.")
    try:
        token = redeem_code(code, request.device_id)
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return {"access_token": token}


@app.post("/v1/auth/verify")
def verify(request: VerifyRequest, authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="인증 정보가 없습니다.")
    token = authorization[7:].strip()
    if not token or len(token) > 256:
        raise HTTPException(status_code=401, detail="인증 정보가 올바르지 않습니다.")
    discord_user_id = verify_session(token, request.device_id)
    if discord_user_id is None:
        raise HTTPException(
            status_code=401,
            detail="인증이 만료되었거나 권한이 취소되었습니다. 디스코드에서 다시 인증하세요.",
        )
    return {"authorized": True, "discord_user_id": discord_user_id}
