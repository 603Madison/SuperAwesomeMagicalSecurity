from __future__ import annotations

import logging
import secrets
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from ..db import hash_secret

log = logging.getLogger("sams.api")


def get_ctx(request: Request) -> Any:
    return request.app.state.ctx


def ensure_admin_token(ctx: Any) -> str | None:
    """If no admin token is configured, mint one on first start and print it once."""
    if ctx.settings.admin_token:
        return None
    if ctx.store.kv_get("admin_token_hash"):
        return None
    token = "sams_" + secrets.token_urlsafe(32)
    ctx.store.kv_set("admin_token_hash", hash_secret(token))
    return token


def check_admin_token(ctx: Any, token: str) -> bool:
    if not token:
        return False
    if ctx.settings.admin_token:
        return secrets.compare_digest(token, ctx.settings.admin_token)
    h = ctx.store.kv_get("admin_token_hash")
    return bool(h) and secrets.compare_digest(hash_secret(token), h)


def _bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def require_admin(request: Request, ctx: Any = Depends(get_ctx)) -> None:
    if not check_admin_token(ctx, _bearer(request)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "admin token required",
                            headers={"WWW-Authenticate": "Bearer"})


def require_agent(kind: str):
    def dep(request: Request, ctx: Any = Depends(get_ctx)) -> dict:
        tok = _bearer(request)
        agent_id, _, key = tok.partition(":")
        agent = ctx.store.authenticate_agent(agent_id, key) if agent_id and key else None
        if not agent or agent["kind"] != kind:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"{kind} credentials required")
        return agent
    return dep


require_host_agent = require_agent("host")
require_probe = require_agent("probe")
