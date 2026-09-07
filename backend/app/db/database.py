from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DATABASE_URL

# Connect args for SQLite to allow multi-threaded access in FastAPI
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes the database, creates missing tables, and applies column migrations."""
    import app.db.models  # noqa: F401 Ensure models are imported before creating tables

    Base.metadata.create_all(bind=engine)

    # Automatic column migration for existing SQLite databases (Stage 1 -> Stage 1.5 upgrade)
    with engine.connect() as conn:
        inspector = inspect(engine)
        if "cases" in inspector.get_table_names():
            columns = {col["name"] for col in inspector.get_columns("cases")}

            column_definitions = [
                ("job_id", "VARCHAR(64)"),
                ("queue_status", "VARCHAR(32)"),
                ("processing_started_at", "DATETIME"),
                ("processing_completed_at", "DATETIME"),
                ("error_message", "VARCHAR(512)"),
            ]

            for col_name, col_type in column_definitions:
                if col_name not in columns:
                    conn.execute(text(f"ALTER TABLE cases ADD COLUMN {col_name} {col_type}"))
            conn.commit()
