"""API routers for querying detection alerts."""

from datetime import datetime, date, time

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.models.database import SessionLocal
from app.repository.alert_repository import get_alerts_filtered, get_alert_by_id
from fastapi import APIRouter, Depends, HTTPException, Query


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)

class AlertResponse(BaseModel):
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

@router.get("/", response_model=list[AlertResponse])
def get_alerts(
    session: Session = Depends(get_db),
    rule_id: str | None = None,
    technique_id: str | None = None,
    source_ip: str | None = None,
    tactic: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[AlertResponse]:
    """Return filtered and paginated detection alerts."""

    start_datetime = None
    end_datetime = None

    if start_date is not None:
        start_datetime = datetime.combine(
            start_date,
            time.min,
        )

    if end_date is not None:
        end_datetime = datetime.combine(
            end_date,
            time.max,
        )

    return get_alerts_filtered(
        session,
        rule_id=rule_id,
        technique_id=technique_id,
        source_ip=source_ip,
        tactic=tactic,
        start_date=start_datetime,
        end_date=end_datetime,
        limit=limit,
        offset=offset,
    )

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    session: Session = Depends(get_db),
) -> AlertResponse:
    """Return one alert by database ID."""

    alert = get_alert_by_id(session, alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )
    return alert
