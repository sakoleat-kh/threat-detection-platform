"""Small SQLAlchemy ORM practice."""

from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

class Base(DeclarativeBase):
    """Base class for ORM models."""

class User(Base):
    """Tiny example database model."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))

engine = create_engine("sqlite:///:memory:")

Base.metadata.create_all(engine)

with Session(engine) as session:
    user = User(name="Alice")

    session.add(user)
    session.commit()

    statement = select(User)
    result = session.execute(statement)

    users = result.scalars().all()

    for row in users:
        print(f"ID: {row.id}, Name: {row.name}")
