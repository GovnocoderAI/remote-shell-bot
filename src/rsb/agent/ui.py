from __future__ import annotations

import asyncio
import hmac
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from rsb.agent.runtime import AgentRuntime
from rsb.errors import AgentError, DeviceOfflineError, NotFoundError
from rsb.server.policy import CapabilityError

INDEX_PATH = Path(__file__).with_name("static") / "index.html"


class UnlockBody(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class DecisionBody(BaseModel):
    approved: bool
    capabilities: list[str] = Field(default_factory=list)


class CapabilitiesBody(BaseModel):
    capabilities: list[str] = Field(default_factory=list)


class PolicyBody(BaseModel):
    capabilities: list[str] = Field(default_factory=list)


def create_ui_app(runtime: AgentRuntime) -> FastAPI:
    app = FastAPI(
        title="RemoteShellBot host panel",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authorize(
        x_rsb_ui_token: Annotated[str | None, Header()] = None,
        token: Annotated[str | None, Query()] = None,
    ) -> None:
        provided = x_rsb_ui_token or token
        if not provided or not hmac.compare_digest(provided, runtime.config.ui_token):
            raise HTTPException(status_code=401, detail="invalid ui token")

    def translate(exc: Exception) -> HTTPException:
        if isinstance(exc, NotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, DeviceOfflineError):
            return HTTPException(status_code=503, detail=str(exc))
        if isinstance(exc, CapabilityError):
            return HTTPException(status_code=400, detail=str(exc))
        if isinstance(exc, AgentError):
            return HTTPException(status_code=423, detail=str(exc))
        return HTTPException(status_code=400, detail=str(exc))

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(
            INDEX_PATH,
            media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/state", dependencies=[Depends(authorize)])
    async def state() -> dict[str, Any]:
        return runtime.state()

    @app.post("/api/unlock", dependencies=[Depends(authorize)])
    async def unlock(body: UnlockBody) -> dict[str, Any]:
        if not runtime.unlock(body.password):
            await asyncio.sleep(0.5)
            raise HTTPException(status_code=401, detail="Неверный пароль хоста.")
        return {"locked": not runtime.unlocked}

    @app.post("/api/lock", dependencies=[Depends(authorize)])
    async def lock() -> dict[str, Any]:
        runtime.lock()
        return {"locked": not runtime.unlocked}

    @app.post("/api/sessions/{session_id}/decision", dependencies=[Depends(authorize)])
    async def decide(session_id: str, body: DecisionBody) -> dict[str, Any]:
        try:
            if body.approved:
                await runtime.approve(session_id, body.capabilities)
            else:
                await runtime.deny(session_id)
        except Exception as exc:
            raise translate(exc) from exc
        return runtime.state()

    @app.post("/api/sessions/{session_id}/capabilities", dependencies=[Depends(authorize)])
    async def capabilities(session_id: str, body: CapabilitiesBody) -> dict[str, Any]:
        try:
            await runtime.set_session_capabilities(session_id, body.capabilities)
        except Exception as exc:
            raise translate(exc) from exc
        return runtime.state()

    @app.post("/api/sessions/{session_id}/close", dependencies=[Depends(authorize)])
    async def close(session_id: str) -> dict[str, Any]:
        try:
            await runtime.close_session(session_id)
        except Exception as exc:
            raise translate(exc) from exc
        return runtime.state()

    @app.get("/api/sessions/{session_id}/screenshot", dependencies=[Depends(authorize)])
    async def screenshot(session_id: str) -> Response:
        try:
            image, _ = runtime.screenshot(session_id)
        except Exception as exc:
            raise translate(exc) from exc
        return Response(
            content=image,
            media_type="image/jpeg",
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/policy", dependencies=[Depends(authorize)])
    async def policy(body: PolicyBody) -> dict[str, Any]:
        try:
            await runtime.update_policy(body.capabilities)
        except Exception as exc:
            raise translate(exc) from exc
        return runtime.state()

    @app.post("/api/grants/{operator_id}/revoke", dependencies=[Depends(authorize)])
    async def revoke_grant(operator_id: int) -> dict[str, Any]:
        try:
            await runtime.revoke_grant(operator_id)
        except Exception as exc:
            raise translate(exc) from exc
        return runtime.state()

    return app
