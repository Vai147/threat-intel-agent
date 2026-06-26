"""FastAPI backend wrapping the agent for the web UI.

Endpoints:
    GET  /api/health
    POST /api/login            {password}      → set session cookie
    POST /api/logout                           → clear session cookie
    GET  /api/me                               → auth status
    GET  /api/feed?days=&limit=                → recent real IOCs (ThreatFox)
    GET  /api/investigate/stream?ioc=&type=&backend=
                                               → SSE: live tool calls + report

`feed` and the stream require auth when APP_PASSWORD is set. The built frontend
(frontend/dist) is served at "/" so the whole app ships as one service.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth
from .agent import iter_threat_intel_agent
from .backends import IntelBackend, MockIntelBackend
from .config import FEED_DEFAULT_DAYS, FEED_DEFAULT_LIMIT
from .report import generate_structured_report

IOC_TYPES = ["ip_address", "file_hash", "domain", "url", "email"]
_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

app = FastAPI(title="Threat Intel Enrichment Agent", version="0.1.0")

# Vite dev server origins (prod is same-origin, so CORS is a dev convenience).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    allow_credentials=True,
)


def _build_backend(name: str) -> IntelBackend:
    if name == "live":
        from .backends_live import LiveIntelBackend

        return LiveIntelBackend()
    return MockIntelBackend()


def _sse(event: dict) -> str:
    """Encode one event as a Server-Sent Events frame."""
    return f"data: {json.dumps(event)}\n\n"


def require_auth(request: Request) -> None:
    """Dependency: allow the request through only when authenticated.

    No-op when auth is disabled (APP_PASSWORD unset).
    """
    if not auth.auth_enabled():
        return
    token = request.cookies.get(auth.COOKIE_NAME)
    if not auth.verify_token(token):
        raise HTTPException(status_code=401, detail="Authentication required")


# --- Auth -------------------------------------------------------------------

class LoginBody(BaseModel):
    password: str


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response) -> dict:
    if not auth.auth_enabled():
        return {"ok": True, "auth_required": False}
    if not auth.password_matches(body.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    secure = request.url.scheme == "https"
    response.set_cookie(
        key=auth.COOKIE_NAME,
        value=auth.issue_token(),
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=auth.SESSION_TTL_SECONDS,
        path="/",
    )
    return {"ok": True, "auth_required": True}


@app.post("/api/logout")
def logout(response: Response) -> dict:
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request) -> dict:
    if not auth.auth_enabled():
        return {"authenticated": True, "auth_required": False}
    authed = auth.verify_token(request.cookies.get(auth.COOKIE_NAME))
    return {"authenticated": authed, "auth_required": True}


# --- Core API ---------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/feed")
def feed(
    days: int = Query(FEED_DEFAULT_DAYS, ge=1, le=7),
    limit: int = Query(FEED_DEFAULT_LIMIT, ge=1, le=50),
    _: None = Depends(require_auth),
):
    """Return recent real IOCs from ThreatFox."""
    from .feeds import ThreatFoxFeed

    try:
        iocs = ThreatFoxFeed().recent(days=days, limit=limit)
    except RuntimeError as exc:  # missing key, etc.
        return JSONResponse(status_code=400, content={"error": str(exc)})
    return {"iocs": [asdict(i) for i in iocs]}


@app.get("/api/investigate/stream")
def investigate_stream(
    ioc: str = Query(..., min_length=1),
    ioc_type: str = Query(..., alias="type"),
    backend: str = Query("mock"),
    _: None = Depends(require_auth),
):
    """Stream the investigation as Server-Sent Events, ending with the report."""
    if ioc_type not in IOC_TYPES:
        return JSONResponse(
            status_code=400, content={"error": f"invalid type: {ioc_type}"}
        )

    def generate() -> Iterator[str]:
        try:
            be = _build_backend(backend)
            yield _sse({"type": "status", "message": "Investigation started"})
            analysis = None
            for event in iter_threat_intel_agent(ioc, ioc_type, be):
                yield _sse(event)
                if event["type"] == "complete":
                    analysis = event["analysis"]
            yield _sse({"type": "status", "message": "Generating report"})
            report = generate_structured_report(analysis or "", ioc, ioc_type)
            yield _sse({"type": "report", "report": report})
            yield _sse({"type": "done"})
        except Exception as exc:  # surface any failure to the client, then close
            yield _sse({"type": "error", "message": str(exc)})

    return StreamingResponse(generate(), media_type="text/event-stream")


# --- Static frontend (mounted last so /api/* wins) --------------------------

if _FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="frontend")
