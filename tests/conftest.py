"""
Fixtures pytest pour les tests Otori Monitoring.
"""

import os
from datetime import datetime, timezone
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Override DATABASE_URL avant d'importer l'app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ENVIRONMENT"] = "testing"
os.environ["GEOIP_ENABLED"] = "false"

from app.db import Base, get_db
from app.main import app


# ═══════════════════════════════════════════════════════════════════════════════
# Database Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
def db_engine():
    """Crée un moteur SQLite en mémoire pour les tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine) -> Generator[Session, None, None]:
    """Crée une session de test."""
    SessionLocal = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Client Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Crée un client de test avec une base de données isolée."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Sample Data Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_event() -> dict:
    """Retourne un événement de test avec timestamp actuel."""
    current_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "timestamp": current_ts,
        "sensor": "test-sensor",
        "honeypot_type": "classic",
        "session_id": "test-session-001",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "protocol": "ssh",
        "event_type": "connect",
        "username": None,
        "password": None,
        "command": None,
        "duration_sec": None,
    }


@pytest.fixture
def sample_command_event() -> dict:
    """Retourne un événement commande de test avec timestamp actuel."""
    current_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "timestamp": current_ts,
        "sensor": "test-sensor",
        "honeypot_type": "classic",
        "session_id": "test-session-001",
        "src_ip": "192.168.1.100",
        "event_type": "command",
        "command": "cat /etc/passwd",
    }
