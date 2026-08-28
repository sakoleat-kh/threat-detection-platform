"""Database configuration for SQLAlchemy."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./alerts.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)