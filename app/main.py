"""
Otori Monitoring - FastAPI Application
Point d'entrée principal de l'API.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, Set

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, SessionLocal, engine, get_db, init_db
from app.kpi import compute_kpi, get_attack_summary, recent_sessions
from app.models import Event, Session as SessionModel
from app.services.geoip import geoip_service
from app.services.classifier import classifier
from app.services.scorer import scorer
from app.services.bot_detector import bot_detector
from app.services.mitre import mitre_mapper

# ═══════════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT,
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Lifespan (startup/shutdown)
# ═══════════════════════════════════════════════════════════════════════════════


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application."""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Database: {'PostgreSQL' if settings.is_postgres else 'SQLite'}")
    logger.info(f"GeoIP: {'enabled' if settings.GEOIP_ENABLED else 'disabled'}")
    logger.info(f"Analytics: {'enabled' if settings.ANALYTICS_ENABLED else 'disabled'}")

    # Initialisation de la base de données
    init_db()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down...")
    geoip_service.close()


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI Application
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Honeypot monitoring and analytics platform",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/web"), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class OtoriEventIn(BaseModel):
    """Schéma d'entrée pour un événement Otori."""

    timestamp: str
    sensor: str
    honeypot_type: str
    session_id: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    event_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    duration_sec: Optional[float] = None


class HealthResponse(BaseModel):
    """Réponse du health check."""

    status: str
    version: str
    environment: str
    database: str
    geoip_enabled: bool
    analytics_enabled: bool


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Manager
# ═══════════════════════════════════════════════════════════════════════════════


class WSManager:
    """Gestionnaire de connexions WebSocket."""

    def __init__(self) -> None:
        self.clients: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        """Accepte une nouvelle connexion WebSocket."""
        await ws.accept()
        self.clients.add(ws)
        logger.debug(f"WebSocket connected. Total clients: {len(self.clients)}")

    def disconnect(self, ws: WebSocket) -> None:
        """Déconnecte un client WebSocket."""
        self.clients.discard(ws)
        logger.debug(f"WebSocket disconnected. Total clients: {len(self.clients)}")

    async def broadcast(self, payload: dict) -> None:
        """Envoie un message à tous les clients connectés."""
        dead: list[WebSocket] = []
        for ws in self.clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WSManager()


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - Health
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """Health check endpoint pour les probes Kubernetes/Docker."""
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        database="postgres" if settings.is_postgres else "sqlite",
        geoip_enabled=settings.GEOIP_ENABLED,
        analytics_enabled=settings.ANALYTICS_ENABLED,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - Pages
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/", response_class=HTMLResponse, tags=["Pages"])
def index() -> HTMLResponse:
    """Page principale du dashboard."""
    with open("app/web/index.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - Ingestion
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/ingest", tags=["Ingestion"])
async def ingest(event: OtoriEventIn, db: Session = Depends(get_db)) -> dict:
    """
    Ingère un événement depuis un honeypot.

    L'événement est enrichi avec:
    - GeoIP (pays, ville, coordonnées)
    - Classification de commande (catégorie, sévérité)
    - Mapping MITRE ATT&CK

    Puis stocké en base et broadcast aux clients WebSocket.
    """
    # Créer l'événement de base
    e = Event(**event.model_dump())

    # Convertir timestamp ISO -> epoch seconds
    try:
        ts = event.timestamp.replace("Z", "+00:00")
        e.ts_epoch = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        e.ts_epoch = datetime.now(timezone.utc).timestamp()

    # ═══════════════════════════════════════════════════════════════════════════
    # Enrichissement GeoIP
    # ═══════════════════════════════════════════════════════════════════════════
    if settings.GEOIP_ENABLED and event.src_ip and event.event_type == "connect":
        geo = geoip_service.lookup(event.src_ip)
        e.country_code = geo.country_code
        e.country_name = geo.country_name
        e.city = geo.city
        e.latitude = geo.latitude
        e.longitude = geo.longitude
        e.asn = geo.asn
        e.asn_org = geo.asn_org

    # ═══════════════════════════════════════════════════════════════════════════
    # Classification de commande
    # ═══════════════════════════════════════════════════════════════════════════
    if settings.ANALYTICS_ENABLED and event.command and event.event_type == "command":
        analysis = classifier.classify(event.command)
        e.command_category = analysis.category.value
        e.command_severity = analysis.severity.value
        e.mitre_techniques = analysis.mitre_techniques

    # Sauvegarder l'événement
    db.add(e)
    db.commit()

    # ═══════════════════════════════════════════════════════════════════════════
    # Mise à jour de la session (si analytics activé)
    # ═══════════════════════════════════════════════════════════════════════════
    if settings.ANALYTICS_ENABLED and event.session_id:
        _update_session(db, event, e)

    # Calculer les KPIs et broadcaster
    kpi = compute_kpi(db)
    recent = recent_sessions(db)

    await ws_manager.broadcast({
        "type": "update",
        "kpi": kpi,
        "recent": recent,
    })

    return {"ok": True}


def _update_session(db: Session, event: OtoriEventIn, e: Event) -> None:
    """Met à jour ou crée la session agrégée."""
    try:
        # Chercher la session existante
        session = db.query(SessionModel).filter(
            SessionModel.session_id == event.session_id
        ).first()

        if not session:
            # Créer une nouvelle session
            session = SessionModel(
                session_id=event.session_id,
                src_ip=event.src_ip,
                sensor=event.sensor,
                honeypot_type=event.honeypot_type,
                start_time=e.ts_epoch,
                country_code=e.country_code,
                country_name=e.country_name,
                city=e.city,
                latitude=e.latitude,
                longitude=e.longitude,
                asn=e.asn,
                asn_org=e.asn_org,
                commands=[],
                categories_seen=[],
                mitre_techniques=[],
                mitre_tactics=[],
                passwords_tried=[],
                bot_signatures=[],
            )
            db.add(session)

        # Mettre à jour selon le type d'événement
        if event.event_type == "connect":
            session.src_ip = event.src_ip
            if e.country_code:
                session.country_code = e.country_code
                session.country_name = e.country_name
                session.city = e.city
                session.latitude = e.latitude
                session.longitude = e.longitude
                session.asn = e.asn
                session.asn_org = e.asn_org

        elif event.event_type == "login_success":
            session.login_success = True
            session.login_attempts += 1
            session.username = event.username
            if event.password and event.password not in (session.passwords_tried or []):
                passwords = session.passwords_tried or []
                passwords.append(event.password)
                session.passwords_tried = passwords[-10:]  # Garder les 10 derniers

        elif event.event_type == "login_failed":
            session.login_attempts += 1
            if not session.username and event.username:
                session.username = event.username
            if event.password and event.password not in (session.passwords_tried or []):
                passwords = session.passwords_tried or []
                passwords.append(event.password)
                session.passwords_tried = passwords[-10:]

        elif event.event_type == "command":
            session.command_count += 1
            # Ajouter la commande à la liste
            commands = session.commands or []
            commands.append(event.command)
            session.commands = commands[-50:]  # Garder les 50 dernières

            # Ajouter la catégorie
            if e.command_category:
                categories = session.categories_seen or []
                if e.command_category not in categories:
                    categories.append(e.command_category)
                    session.categories_seen = categories

                # Flags
                if e.command_category == "credential":
                    session.has_credential_access = True
                elif e.command_category == "persist":
                    session.has_persistence = True
                elif e.command_category == "lateral":
                    session.has_lateral_movement = True
                elif e.command_category == "exfil":
                    session.has_exfiltration = True
                elif e.command_category == "impact":
                    session.has_impact = True

            # Ajouter les techniques MITRE
            if e.mitre_techniques:
                techniques = session.mitre_techniques or []
                for t in e.mitre_techniques:
                    if t not in techniques:
                        techniques.append(t)
                session.mitre_techniques = techniques

        elif event.event_type == "closed":
            session.end_time = e.ts_epoch
            session.duration_sec = event.duration_sec

            # Calculer le score final de la session
            if settings.SESSION_SCORING_ENABLED:
                _score_session(session)

        db.commit()

    except Exception as ex:
        logger.error(f"Error updating session: {ex}")
        db.rollback()


def _score_session(session: SessionModel) -> None:
    """Calcule le score de dangerosité de la session."""
    commands = session.commands or []

    # Scoring
    score = scorer.score_session(
        commands=commands,
        login_success=session.login_success,
        login_attempts=session.login_attempts,
        duration_sec=session.duration_sec,
    )

    session.danger_score = score.total_score
    session.danger_level = score.danger_level.value

    # MITRE mapping
    if session.mitre_techniques:
        mapping = mitre_mapper.map_techniques(session.mitre_techniques)
        session.mitre_tactics = list(mapping.tactics_coverage.keys())
        session.attack_phase = mapping.attack_phase
        session.kill_chain_progress = mapping.kill_chain_progress

    # Bot detection
    if settings.BOT_DETECTION_ENABLED:
        bot_analysis = bot_detector.analyze(
            commands=commands,
            login_attempts=session.login_attempts,
            passwords=session.passwords_tried,
        )
        session.attacker_type = bot_analysis.attacker_type.value
        session.bot_confidence = bot_analysis.confidence
        session.bot_signatures = bot_analysis.signatures_matched


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - KPIs
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/kpi", tags=["Analytics"])
def get_kpi(
    hours: int = 24,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les KPIs sur une fenêtre de temps."""
    return compute_kpi(db, hours=hours)


@app.get("/kpi/summary", tags=["Analytics"])
def get_kpi_summary(
    hours: int = 24,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère un résumé exécutif des attaques."""
    return get_attack_summary(db, hours=hours)


@app.get("/sessions/recent", tags=["Analytics"])
def get_recent(
    limit: int = 10,
    db: Session = Depends(get_db),
) -> list:
    """Récupère les sessions récentes."""
    return recent_sessions(db, limit=limit)


@app.get("/sessions/{session_id}", tags=["Analytics"])
def get_session_detail(
    session_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les détails d'une session spécifique."""
    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()

    if not session:
        return {"error": "Session not found"}

    # Récupérer les événements de la session
    events = db.query(Event).filter(
        Event.session_id == session_id
    ).order_by(Event.ts_epoch).all()

    return {
        "session": {
            "session_id": session.session_id,
            "src_ip": session.src_ip,
            "country_code": session.country_code,
            "country_name": session.country_name,
            "city": session.city,
            "asn_org": session.asn_org,
            "honeypot_type": session.honeypot_type,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "duration_sec": session.duration_sec,
            "login_success": session.login_success,
            "login_attempts": session.login_attempts,
            "username": session.username,
            "command_count": session.command_count,
            "danger_score": session.danger_score,
            "danger_level": session.danger_level,
            "attacker_type": session.attacker_type,
            "bot_confidence": session.bot_confidence,
            "categories_seen": session.categories_seen,
            "mitre_techniques": session.mitre_techniques,
            "mitre_tactics": session.mitre_tactics,
            "attack_phase": session.attack_phase,
            "kill_chain_progress": session.kill_chain_progress,
        },
        "events": [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "command": e.command,
                "command_category": e.command_category,
                "command_severity": e.command_severity,
                "username": e.username,
                "mitre_techniques": e.mitre_techniques,
            }
            for e in events
        ],
        "commands": session.commands or [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - MITRE
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/mitre/techniques", tags=["MITRE"])
def get_mitre_techniques(
    hours: int = 24,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les techniques MITRE observées."""
    from collections import Counter

    # Récupérer toutes les techniques des événements
    events = db.query(Event.mitre_techniques).filter(
        Event.mitre_techniques.isnot(None)
    ).all()

    technique_counter: Counter = Counter()
    for (techniques,) in events:
        if techniques:
            technique_counter.update(techniques)

    # Enrichir avec les détails MITRE
    results = []
    for tid, count in technique_counter.most_common(20):
        technique = mitre_mapper.get_technique(tid)
        if technique:
            results.append({
                "technique_id": tid,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
                "count": count,
                "url": technique.url,
            })
        else:
            results.append({
                "technique_id": tid,
                "technique_name": "Unknown",
                "tactic": "Unknown",
                "count": count,
                "url": None,
            })

    return {
        "techniques": results,
        "total_unique": len(technique_counter),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - WebSocket
# ═══════════════════════════════════════════════════════════════════════════════


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """WebSocket pour les mises à jour en temps réel."""
    await ws_manager.connect(ws)
    try:
        while True:
            # Garde la connexion ouverte
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════


def run() -> None:
    """Entry point pour la commande `otori-server`."""
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    run()
