"""API routers for alert statistics."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.models.database import SessionLocal
from app.repository.alert_repository import get_alert_stats

router = APIRouter(
    prefix="/stats",
    tags=["stats"],
)

def get_db():
    """Provide a database session for an API request."""

    with SessionLocal() as session:
        yield session

@router.get("/")
def get_stats(
    session: Session = Depends(get_db),
) -> dict[str, dict[str, int]]:
    """Return alert counts grouped by rule, technique, and tactic."""

    return get_alert_stats(session)