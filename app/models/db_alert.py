"""SQLAlchemy ORM model for persistent detection alerts."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base

class AlertRecord(Base):
    """Database repersentation of a detection alert."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String,
        index=True,
        nullable=False,
    )

    rule_name: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String,
        index=True,
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    technique_id: Mapped[str | None] = mapped_column(
        String,
        index=True,
        nullable=True,
    )

    technique_name: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    tactic: Mapped[str | None] = mapped_column(
        String,
        index=True,
        nullable=True,
    )

    source_type: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String,
        index=True,
        nullable=True,
    )

    username: Mapped[str | None] = mapped_column(
        String,
        index=True,
        nullable=True,
    )

    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )

    raw_event_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )