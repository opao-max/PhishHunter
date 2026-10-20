"""FastAPI application powering the PhishHunter SOC console.

Routes
------
``GET  /``              self-contained HTML dashboard
``GET  /api/health``    liveness probe
``GET  /api/samples``   metadata for ``data/emails/*.json`` (optionally the
                        full email payload via ``?include_email=true``)
``POST /api/analyze``   analyse one email object, return the full report

Security notes
--------------
* The server never accepts a file path from the client; the only files it
  reads are the operator-provided samples under ``data/emails``.
* The analysis agent is constructed lazily from environment settings and is
  reused across requests, so a browser refresh cannot trigger re-initialisation
  storms.
* Request payloads are validated before they reach the agent; malformed input
  returns HTTP 400 instead of a stack trace.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..config import DEFAULT_EMAIL_DIR, Settings

TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "index.html"

# Fields that make a JSON object recognisably an email we can analyse.
_EMAIL_FIELDS = (
    "headers",
    "body_text",
    "body_html",
    "links",
    "attachments",
    "images",
    "subject",
    "from",
    "to",
)
_LIST_FIELDS = ("links", "attachments", "images")
_MAX_BODY_BYTES = 1_000_000
_MAX_TEXT_CHARS = 500_000
_MAX_LIST_ITEMS = {"links": 200, "attachments": 50, "images": 20}
_MAX_HEADERS = 100

app = FastAPI(
    title="PhishHunter",
    version=__version__,
    description="证据驱动的多模态钓鱼邮件检测智能体",
)

_agent_lock = Lock()
_agent: Any = None


# --------------------------------------------------------------------------- #
# lazy agent
# --------------------------------------------------------------------------- #


def _get_agent() -> Any:
    """Build the agent once, on first use (settings come from the env)."""
    global _agent
    if _agent is None:
        with _agent_lock:
            if _agent is None:
                from ..agent import PhishHunterAgent

                _agent = PhishHunterAgent(settings=Settings.from_env())
    return _agent


def _agent_or_503() -> Any:
    try:
        return _get_agent()
    except Exception as exc:  # noqa: BLE001 - surface a clean service error
        raise HTTPException(
            status_code=503,
            detail=f"分析引擎初始化失败：{type(exc).__name__}: {exc}",
        ) from exc


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def _validate_email_payload(email: Any) -> dict[str, Any]:
    if not isinstance(email, dict) or not email:
        raise HTTPException(status_code=400, detail="请求体必须是非空 JSON 对象")
    if not any(key in email for key in _EMAIL_FIELDS):
        raise HTTPException(
            status_code=400,
            detail=(
                "邮件对象缺少可分析字段，请至少提供 "
                "headers、body_text、body_html、links 或 attachments 之一"
            ),
        )
    headers = email.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise HTTPException(status_code=400, detail="headers 必须是 JSON 对象")
    if isinstance(headers, dict):
        if len(headers) > _MAX_HEADERS:
            raise HTTPException(status_code=413, detail="headers 数量过多")
        for key, value in headers.items():
            if len(str(key)) > 256 or len(str(value)) > 8192:
                raise HTTPException(status_code=413, detail="header 字段过长")
    for field_name in ("body_text", "body_html"):
        value = email.get(field_name)
        if isinstance(value, str) and len(value) > _MAX_TEXT_CHARS:
            raise HTTPException(status_code=413, detail=f"{field_name} 过长")
    for field_name in _LIST_FIELDS:
        value = email.get(field_name)
        if value is not None and not isinstance(value, list):
            raise HTTPException(
                status_code=400, detail=f"{field_name} 必须是 JSON 数组"
            )
        if isinstance(value, list) and len(value) > _MAX_LIST_ITEMS[field_name]:
            raise HTTPException(status_code=413, detail=f"{field_name} 数量过多")
    return email


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    try:
        html = TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"界面模板不可用：{exc}"
        ) from exc
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "service": "phishhunter"}


@app.get("/api/samples")
def list_samples(
    include_email: bool = Query(
        False, description="同时返回完整的邮件 JSON，供前端载入编辑器"
    )
) -> list[dict[str, Any]]:
    """List operator-provided samples. Never accepts a client file path."""
    samples: list[dict[str, Any]] = []
    if not DEFAULT_EMAIL_DIR.is_dir():
        return samples
    for path in sorted(DEFAULT_EMAIL_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
        subject = str(data.get("subject") or "")
        if not subject:
            for key, value in headers.items():
                if str(key).strip().lower() == "subject":
                    subject = str(value or "")
                    break
        item: dict[str, Any] = {
            "id": str(data.get("id") or path.stem),
            "filename": path.name,
            "subject": subject,
            "label": str(data.get("label") or ""),
            "expected_action": str(data.get("expected_action") or ""),
        }
        if include_email:
            item["email"] = data
        samples.append(item)
    return samples


@app.post("/api/analyze")
async def analyze(request: Request) -> JSONResponse:
    """Analyse an email object (``{...}`` or ``{"email": {...}}``)."""
    length_header = request.headers.get("content-length", "")
    try:
        if length_header and int(length_header) > _MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="请求体过大")
    except ValueError:
        pass
    body_bytes = await request.body()
    if len(body_bytes) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="请求体过大")
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="请求体不是有效的 JSON")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")

    nested = body.get("email")
    email = nested if isinstance(nested, dict) and not (
        {"headers", "body_text", "body_html"} & set(body)
    ) else body
    email = _validate_email_payload(email)

    agent = _agent_or_503()
    try:
        report = await run_in_threadpool(agent.analyze, email)
    except Exception as exc:  # noqa: BLE001 - invalid analysis input
        raise HTTPException(
            status_code=400,
            detail=f"邮件分析失败：{type(exc).__name__}: {exc}",
        ) from exc

    return JSONResponse(jsonable_encoder(report.to_dict()))


__all__ = ["app"]