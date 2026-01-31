"""
Configuration de la base de données.
Supporte SQLite (dev) et PostgreSQL (production).
"""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings

# ─────────────────────────────────────────────────────────────────────────────
# Configuration du moteur selon le type de base
# ─────────────────────────────────────────────────────────────────────────────

if settings.is_sqlite:
    # SQLite: mode développement
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=settings.DEBUG,
    )
else:
    # PostgreSQL: mode production
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,  # Vérifie la connexion avant utilisation
        echo=settings.DEBUG,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Session factory
# ─────────────────────────────────────────────────────────────────────────────

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# ─────────────────────────────────────────────────────────────────────────────
# Base pour les modèles
# ─────────────────────────────────────────────────────────────────────────────

Base = declarative_base()


# ─────────────────────────────────────────────────────────────────────────────
# Dependency injection pour FastAPI
# ─────────────────────────────────────────────────────────────────────────────

def get_db() -> Generator[Session, None, None]:
    """
    Dépendance FastAPI pour obtenir une session DB.

    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            ...

    Yields:
        Session: Session SQLAlchemy.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager pour usage hors FastAPI.

    Usage:
        with get_db_context() as db:
            db.query(...)

    Yields:
        Session: Session SQLAlchemy.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Initialisation de la base
# ─────────────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """
    Crée toutes les tables définies dans les modèles.
    À appeler au démarrage de l'application.
    """
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """
    Supprime toutes les tables (usage tests uniquement).
    """
    Base.metadata.drop_all(bind=engine)


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

def check_db_connection() -> bool:
    """
    Vérifie que la connexion à la base fonctionne.

    Returns:
        bool: True si la connexion est OK.
    """
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
