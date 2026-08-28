"""Initialize the SQLite database."""

from app.models.database import init_db
from app.models.db_alert import AlertRecord

def main() -> None:
    """Create the database tables."""
    init_db()
    print("Database initialized successfully.")

if __name__ == "__main__":
    main()