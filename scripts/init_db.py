"""Initialize the SQLite database."""

from app.models.database import init_db


def main() -> None:
    """Create the database tables."""
    init_db()
    print("Database initialized successfully.")

if __name__ == "__main__":
    main()