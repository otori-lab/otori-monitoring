"""
Modèles SQLAlchemy pour Otori Monitoring.
"""

import json

from sqlalchemy import Boolean, Column, Float, Integer, String, Text
from sqlalchemy.types import TypeDecorator

from app.db import Base


class JSONEncodedList(TypeDecorator):
    """Stocke une liste Python en JSON string (compatible SQLite et PostgreSQL)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, _dialect):
        if value is not None:
            return json.dumps(value)
        return "[]"

    def process_result_value(self, value, _dialect):
        if value is not None:
            return json.loads(value)
        return []


class Event(Base):
    """Événement brut depuis un honeypot."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Champs OTORI de base
    # ═══════════════════════════════════════════════════════════════════════════
    timestamp = Column(String, index=True)  # ISO 8601
    ts_epoch = Column(Float, index=True)  # timestamp en secondes (UTC)
    sensor = Column(String, index=True)
    honeypot_type = Column(String, index=True)  # classic / ia
    session_id = Column(String, index=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Réseau
    # ═══════════════════════════════════════════════════════════════════════════
    src_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Événement
    # ═══════════════════════════════════════════════════════════════════════════
    event_type = Column(String, index=True)  # connect / command / login_* / closed
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    command = Column(String, nullable=True)
    duration_sec = Column(Float, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # GeoIP - Géolocalisation
    # ═══════════════════════════════════════════════════════════════════════════
    country_code = Column(String(3), nullable=True, index=True)
    country_name = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Classification de commande
    # ═══════════════════════════════════════════════════════════════════════════
    command_category = Column(String, nullable=True, index=True)  # recon, persist, etc.
    command_severity = Column(String, nullable=True, index=True)  # critical, high, etc.
    mitre_techniques = Column(JSONEncodedList, nullable=True)  # ["T1059", "T1082"]


class Session(Base):
    """Session agrégée avec scoring et analyse."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Informations de base
    # ═══════════════════════════════════════════════════════════════════════════
    src_ip = Column(String, index=True)
    sensor = Column(String, index=True)
    honeypot_type = Column(String, index=True)

    # Timing
    start_time = Column(Float, index=True)  # epoch
    end_time = Column(Float, nullable=True)
    duration_sec = Column(Float, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Authentification
    # ═══════════════════════════════════════════════════════════════════════════
    login_success = Column(Boolean, default=False)
    login_attempts = Column(Integer, default=0)
    username = Column(String, nullable=True)
    passwords_tried = Column(JSONEncodedList, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # GeoIP
    # ═══════════════════════════════════════════════════════════════════════════
    country_code = Column(String(3), nullable=True, index=True)
    country_name = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String, nullable=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # Commandes
    # ═══════════════════════════════════════════════════════════════════════════
    command_count = Column(Integer, default=0)
    commands = Column(JSONEncodedList, nullable=True)  # Liste des commandes
    unique_commands = Column(Integer, default=0)

    # ═══════════════════════════════════════════════════════════════════════════
    # Scoring et analyse
    # ═══════════════════════════════════════════════════════════════════════════
    danger_score = Column(Integer, default=0, index=True)  # 0-100
    danger_level = Column(String, default="minimal", index=True)  # minimal/low/medium/high/critical

    # Catégories de commandes observées
    categories_seen = Column(JSONEncodedList, nullable=True)  # ["recon", "persist"]
    has_credential_access = Column(Boolean, default=False)
    has_persistence = Column(Boolean, default=False)
    has_lateral_movement = Column(Boolean, default=False)
    has_exfiltration = Column(Boolean, default=False)
    has_impact = Column(Boolean, default=False)

    # MITRE
    mitre_techniques = Column(JSONEncodedList, nullable=True)
    mitre_tactics = Column(JSONEncodedList, nullable=True)
    attack_phase = Column(String, nullable=True)
    kill_chain_progress = Column(Float, default=0.0)

    # ═══════════════════════════════════════════════════════════════════════════
    # Détection Bot
    # ═══════════════════════════════════════════════════════════════════════════
    attacker_type = Column(String, default="unknown", index=True)  # bot/human/hybrid/unknown
    bot_confidence = Column(Float, default=0.0)
    bot_signatures = Column(JSONEncodedList, nullable=True)


class AttackStats(Base):
    """Statistiques agrégées par période (pour KPIs rapides)."""

    __tablename__ = "attack_stats"

    id = Column(Integer, primary_key=True, index=True)
    period = Column(String, index=True)  # "2026-01-31", "2026-01-31-14" (hour)
    period_type = Column(String, index=True)  # "day", "hour"

    # Compteurs
    total_sessions = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    total_commands = Column(Integer, default=0)
    login_attempts = Column(Integer, default=0)
    login_success = Column(Integer, default=0)

    # Par niveau de danger
    sessions_critical = Column(Integer, default=0)
    sessions_high = Column(Integer, default=0)
    sessions_medium = Column(Integer, default=0)
    sessions_low = Column(Integer, default=0)

    # Par type d'attaquant
    sessions_bot = Column(Integer, default=0)
    sessions_human = Column(Integer, default=0)

    # Top pays (JSON)
    top_countries = Column(JSONEncodedList, nullable=True)

    # Top catégories d'attaque
    top_categories = Column(JSONEncodedList, nullable=True)

    # Top MITRE techniques
    top_mitre = Column(JSONEncodedList, nullable=True)
