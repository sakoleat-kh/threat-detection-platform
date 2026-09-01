"""API routers for log ingestion."""

from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.detection_engine import build_engine
from app.services.ingestion import ingest_logs

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)

@router.post("/")
async def ingest_file(
    file: UploadFile = File(...),
    log_type: str = Form(...),
) -> dict[str, int]:
    """Ingest an uploaded authentication or access log file."""

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
            reference_date=datetime.now(),
        )

        lines_processed = (
            result.auth_lines_processed
            + result.access_lines_processed
        )

        return {
            "lines_processed": lines_processed,
            "alerts_generated": result.alerts_generated,
        }
    finally:
        temporary_path.unlink(missing_ok=True)