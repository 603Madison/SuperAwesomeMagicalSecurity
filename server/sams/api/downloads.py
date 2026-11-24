"""Unauthenticated agent/probe downloads and the one-line Linux installer.

Binaries are public (they contain no secrets); enrollment still needs a one-time
token. ``/install.sh`` is the agent installer with this server's URL filled in.
Because that script is piped into a root shell, the URL inserted into it is
validated strictly and never taken from an unvalidated Host header.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

from .deps import get_ctx

router = APIRouter()
SAFE_NAME = re.compile(r"^(sams-(agent|probe)[A-Za-z0-9._-]*|SHA256SUMS)$")
SAFE_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
REPO_INSTALLER = Path(__file__).resolve().parents[3] / "agent" / "packaging" / "install.sh"


def dist_dir(ctx: Any) -> Optional[Path]:
    for d in (ctx.settings.dist_dir, ctx.settings.data_dir / "dist"):
        if d and Path(d).is_dir():
            return Path(d)
    return None


def server_url(ctx: Any, request: Request) -> str:
    url = (ctx.settings.public_url or str(request.base_url)).rstrip("/")
    if not SAFE_URL.match(url):
        raise HTTPException(400, "server URL is not usable in an installer; set public_url in sams.yaml")
    return url


@router.get("/install.sh", include_in_schema=False)
def install_script(request: Request, ctx: Any = Depends(get_ctx)) -> PlainTextResponse:
    d = dist_dir(ctx)
    src = d / "install.sh" if d and (d / "install.sh").is_file() else REPO_INSTALLER
    if not src.is_file():
        raise HTTPException(404, "installer not available")
    body = src.read_text().replace("__SAMS_SERVER__", server_url(ctx, request), 1)
    return PlainTextResponse(body, media_type="text/x-shellscript")


@router.get("/downloads")
def list_downloads(ctx: Any = Depends(get_ctx)) -> dict:
    d = dist_dir(ctx)
    files = sorted(p.name for p in d.iterdir() if p.is_file() and SAFE_NAME.match(p.name)) if d else []
    return {"files": files}


@router.get("/downloads/{name}", include_in_schema=False)
def download(name: str, ctx: Any = Depends(get_ctx)) -> FileResponse:
    d = dist_dir(ctx)
    if not d or not SAFE_NAME.match(name):
        raise HTTPException(404, "not found")
    path = d / name
    if not path.is_file():
        raise HTTPException(404, "not found")
    media = "text/plain" if name == "SHA256SUMS" else "application/octet-stream"
    return FileResponse(path, media_type=media, filename=name)
