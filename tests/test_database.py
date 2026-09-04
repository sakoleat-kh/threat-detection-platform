"""Tests for database interactions."""

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.models.database import Base
from app.models import db_alert
import app.models.database as database

def test_init_db_creates_tables(monkeypatch):
    """Database initialization creates the required tables."""

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(
        database,
        "SessionLocal",
        sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
        ),
    )

    database.init_db()

    inspector = inspect(engine)
    tables = inspector.get_table_names()

    assert "alerts" in tables

    engine.dispose()