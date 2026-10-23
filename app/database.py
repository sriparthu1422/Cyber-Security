"""
app/database.py — SQLAlchemy database engine and session management.

Uses synchronous SQLAlchemy with SQLite.
Sessions are managed with a context manager to ensure proper cleanup.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from contextlib import contextmanager
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Create the SQLAlchemy engine
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
    echo=False,  # Set True to see SQL queries (useful for debugging)
)

# Enable WAL mode for better concurrent read performance with SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy models."""
    pass


@contextmanager
def get_db_session():
    """
    Context manager for database sessions.
    Ensures sessions are properly closed and rolled back on error.
    
    Usage:
        with get_db_session() as db:
            db.add(some_record)
            db.commit()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {e}")
        raise
    finally:
        session.close()


def get_db():
    """
    FastAPI dependency that provides a database session per request.
    Yields the session and ensures it's closed after the request.
    
    Usage in FastAPI:
        @router.get("/items")
        def read_items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize all database tables.
    Called once at application startup.
    Safe to call multiple times — only creates tables that don't exist.
    """
    # Import all models so SQLAlchemy knows about them
    from app.models import detection_event, dataset_import, model_run  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
