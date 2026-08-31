"""API routers for querying detection alerts."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.models.database import SessionLocal
from app.repository.alert_repository import get_alerts_filtered

router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)

class AalertResponse(BaseModel):
    """Response model for a persisted detection alert."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    rule_name: str
    severity: str
    description: str
    technique_id: str | None
    technique_name: str | None
    tactic: str | None
    source_type: str
    source_ip: str | None
    username: str | None
    event_timestamp: datetime
    created_at: datetime
    raw_event_json: dict

def get_db():
    """Provide a database session for an API request."""

    with SessionLocal() as session:
        yield session

@router.get("/", response_model=list[AalertResponse])
def get_alerts(
    session: Session = Depends(get_db),
    rule_id: str | None = None,
    technique_id: str | None = None,
    source_ip: str | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[AalertResponse]:
    """Return filtered and paginated detection alerts."""

    return get_alerts_filtered(
        session,
        rule_id=rule_id,
        technique_id=technique_id,
        source_ip=source_ip,
        limit=limit,
        offset=offset,
    )

