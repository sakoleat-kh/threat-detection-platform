"""API routers for log ingestion."""

from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.detection_engine import build_engine
from app.services.ingestion import ingest_logs

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)

RuleName = Literal[
    "all",
    "ssh_brute_force",
    "successful_after_failures",
    "excessive_sudo",
    "new_user_creation",
    "directory_scanning",
    "sql_injection",
    "xss_attempt",
    "suspicious_user_agent",
]


@router.post("/")
async def ingest_file(
    file: UploadFile = File(...),  # noqa: B008
    log_type: str = Form(...),
    max_alerts: int | None = Form(default=None, ge=1),  # noqa: B008
    rule: RuleName = Form(default="all"),  # noqa: B008
) -> dict[str, int]:
    """Ingest an uploaded authentication or access log file.

    If rule is not "all", only alerts from that rule are saved.
    If max_alerts is set, at most that many new alerts are saved.
    """

    if log_type not in ("auth", "access"):
        raise HTTPException(
            status_code=400,
            detail="log_type must be 'auth' or 'access'",
        )

    suffix = Path(file.filename or "").suffix

    with NamedTemporaryFile(
        mode="wb",
        suffix=suffix,
        delete=False,
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)

        while chunk := await file.read(1024 * 1024):
            temporary_file.write(chunk)

    try:
        result = ingest_logs(
            auth_log_path=(
                temporary_path if log_type == "auth" else None
            ),
            access_log_path=(
                temporary_path if log_type == "access" else None
            ),
            engine=build_engine(),
            reference_date=datetime.now(),  # noqa: DTZ005
            max_new_alerts=max_alerts,
            only_rule=None if rule == "all" else rule,
        )

        lines_processed = (
            result.auth_lines_processed
            + result.access_lines_processed
        )

        return {
            "lines_processed": lines_processed,
            "alerts_generated": result.alerts_generated,
            "alerts_saved": result.alerts_saved,
        }
    finally:
        temporary_path.unlink(missing_ok=True)