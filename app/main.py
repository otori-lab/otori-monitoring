"""
Otori Monitoring - FastAPI Application
Point d'entrée principal de l'API.
"""

import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db, init_db
from app.kpi import compute_kpi, get_attack_summary, recent_sessions
from app.models import Event, Sensor
from app.models import Session as SessionModel
from app.services.bot_detector import bot_detector
from app.services.classifier import classifier
from app.services.geoip import geoip_service
from app.services.mitre import mitre_mapper
from app.services.scorer import scorer

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
async def lifespan(_app: FastAPI):
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
app.mount("/css", StaticFiles(directory="app/web/css"), name="css")
app.mount("/js", StaticFiles(directory="app/web/js"), name="js")


# ═══════════════════════════════════════════════════════════════════════════════
# Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class OtoriEventIn(BaseModel):
    """Schéma d'entrée pour un événement Otori."""

    timestamp: str
    sensor: str
    honeypot_type: str
    session_id: str | None = None

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None

    event_type: str
    username: str | None = None
    password: str | None = None
    command: str | None = None
    duration_sec: float | None = None

    # Optional geo data (if not provided, will be looked up via GeoIP)
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn_org: str | None = None


class HealthResponse(BaseModel):
    """Réponse du health check."""

    status: str
    version: str
    environment: str
    database: str
    geoip_enabled: bool
    analytics_enabled: bool


class SensorRegisterIn(BaseModel):
    """Schéma d'entrée pour l'enregistrement d'un sensor."""

    hostname: str
    honeypot_type: str  # ia / classic
    ip: str
    profile_name: str | None = None


class SensorRegisterOut(BaseModel):
    """Réponse de l'enregistrement d'un sensor."""

    sensor_id: str
    token: str


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Manager
# ═══════════════════════════════════════════════════════════════════════════════


class WSManager:
    """Gestionnaire de connexions WebSocket."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

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
# Routes - Registration
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/register", response_model=SensorRegisterOut, tags=["Registration"])
def register_sensor(sensor: SensorRegisterIn, db: Session = Depends(get_db)) -> SensorRegisterOut:
    """
    Enregistre un nouveau honeypot auprès du monitoring.

    Génère un sensor_id unique au format: {uuid}-{ip}-{hostname}
    et un token pour l'authentification future.

    Si le honeypot est déjà enregistré (même ip + hostname), retourne les credentials existants.
    """
    # Vérifier si déjà enregistré
    existing = (
        db.query(Sensor)
        .filter(Sensor.ip == sensor.ip, Sensor.hostname == sensor.hostname)
        .first()
    )

    if existing:
        # Mettre à jour last_seen
        existing.last_seen = datetime.now(UTC).timestamp()
        db.commit()
        logger.info(f"Sensor reconnected: {existing.sensor_id}")
        return SensorRegisterOut(sensor_id=existing.sensor_id, token=existing.token)

    # Générer un nouvel enregistrement
    sensor_uuid = str(uuid.uuid4())[:8]
    sensor_id = f"{sensor_uuid}-{sensor.ip}-{sensor.hostname}"
    token = secrets.token_urlsafe(32)

    new_sensor = Sensor(
        sensor_id=sensor_id,
        uuid=sensor_uuid,
        hostname=sensor.hostname,
        ip=sensor.ip,
        honeypot_type=sensor.honeypot_type,
        profile_name=sensor.profile_name,
        token=token,
        registered_at=datetime.now(UTC).timestamp(),
        last_seen=datetime.now(UTC).timestamp(),
    )

    db.add(new_sensor)
    db.commit()

    logger.info(f"New sensor registered: {sensor_id} (type={sensor.honeypot_type})")
    return SensorRegisterOut(sensor_id=sensor_id, token=token)


@app.get("/sensors", tags=["Registration"])
def list_sensors(db: Session = Depends(get_db)) -> list[dict]:
    """Liste tous les sensors enregistrés."""
    sensors = db.query(Sensor).order_by(Sensor.registered_at.desc()).all()
    return [
        {
            "sensor_id": s.sensor_id,
            "hostname": s.hostname,
            "ip": s.ip,
            "honeypot_type": s.honeypot_type,
            "profile_name": s.profile_name,
            "registered_at": s.registered_at,
            "last_seen": s.last_seen,
        }
        for s in sensors
    ]


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
        e.ts_epoch = datetime.fromisoformat(ts).replace(tzinfo=UTC).timestamp()
    except Exception:
        e.ts_epoch = datetime.now(UTC).timestamp()

    # ═══════════════════════════════════════════════════════════════════════════
    # Enrichissement GeoIP (use provided data or lookup)
    # ═══════════════════════════════════════════════════════════════════════════
    if event.src_ip and event.event_type == "connect":
        # Use provided geo data if available
        if event.latitude is not None and event.longitude is not None:
            e.country_code = event.country_code
            e.country_name = event.country_name
            e.city = event.city
            e.latitude = event.latitude
            e.longitude = event.longitude
            e.asn_org = event.asn_org
        # Otherwise, lookup via GeoIP service
        elif settings.GEOIP_ENABLED:
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
    # Mise à jour du last_seen du sensor
    # ═══════════════════════════════════════════════════════════════════════════
    if event.sensor:
        sensor = db.query(Sensor).filter(Sensor.sensor_id == event.sensor).first()
        if sensor:
            sensor.last_seen = datetime.now(UTC).timestamp()
            db.commit()

    # ═══════════════════════════════════════════════════════════════════════════
    # Mise à jour de la session (si analytics activé)
    # ═══════════════════════════════════════════════════════════════════════════
    if settings.ANALYTICS_ENABLED and event.session_id:
        _update_session(db, event, e)

    # Calculer les KPIs et broadcaster
    kpi = compute_kpi(db)
    recent = recent_sessions(db)

    await ws_manager.broadcast(
        {
            "type": "update",
            "kpi": kpi,
            "recent": recent,
        }
    )

    return {"ok": True}


def _update_session(db: Session, event: OtoriEventIn, e: Event) -> None:
    """Met à jour ou crée la session agrégée."""
    try:
        # Chercher la session existante
        session = db.query(SessionModel).filter(SessionModel.session_id == event.session_id).first()

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
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()

    if not session:
        return {"error": "Session not found"}

    # Récupérer les événements de la session
    events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.ts_epoch).all()

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
# Routes - Interactive Data (Cross-reference queries)
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/commands/by-ip/{ip}", tags=["Interactive"])
def get_commands_by_ip(
    ip: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list:
    """Récupère toutes les commandes exécutées par une IP spécifique."""
    events = (
        db.query(Event)
        .filter(Event.src_ip == ip, Event.event_type == "command")
        .order_by(Event.ts_epoch.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "command": e.command,
            "timestamp": e.timestamp,
            "ts_epoch": e.ts_epoch,
            "session_id": e.session_id,
            "category": e.command_category,
            "severity": e.command_severity,
            "mitre_techniques": e.mitre_techniques,
        }
        for e in events
    ]


@app.get("/commands/search", tags=["Interactive"])
def search_command(
    q: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> dict:
    """Recherche les IPs qui ont exécuté une commande spécifique."""
    from sqlalchemy import func

    events = (
        db.query(Event)
        .filter(Event.event_type == "command", Event.command.contains(q))
        .order_by(Event.ts_epoch.desc())
        .limit(limit)
        .all()
    )

    # Group by IP
    ip_data = {}
    for e in events:
        if e.src_ip not in ip_data:
            ip_data[e.src_ip] = {
                "ip": e.src_ip,
                "country_code": e.country_code,
                "count": 0,
                "first_seen": e.ts_epoch,
                "last_seen": e.ts_epoch,
                "executions": [],
            }
        ip_data[e.src_ip]["count"] += 1
        ip_data[e.src_ip]["last_seen"] = max(ip_data[e.src_ip]["last_seen"], e.ts_epoch)
        ip_data[e.src_ip]["first_seen"] = min(ip_data[e.src_ip]["first_seen"], e.ts_epoch)
        if len(ip_data[e.src_ip]["executions"]) < 10:
            ip_data[e.src_ip]["executions"].append(
                {
                    "command": e.command,
                    "timestamp": e.timestamp,
                    "session_id": e.session_id,
                }
            )

    return {
        "query": q,
        "total_executions": len(events),
        "unique_ips": len(ip_data),
        "ips": sorted(ip_data.values(), key=lambda x: x["count"], reverse=True),
    }


@app.get("/auth/details", tags=["Interactive"])
def get_auth_details(
    auth_type: str = "all",  # success, failed, all
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list:
    """Récupère les détails des événements d'authentification."""
    query = db.query(Event)

    if auth_type == "success":
        query = query.filter(Event.event_type == "login_success")
    elif auth_type == "failed":
        query = query.filter(Event.event_type == "login_failed")
    else:
        query = query.filter(Event.event_type.in_(["login_success", "login_failed"]))

    events = query.order_by(Event.ts_epoch.desc()).limit(limit).all()

    return [
        {
            "timestamp": e.timestamp,
            "ts_epoch": e.ts_epoch,
            "event_type": e.event_type,
            "src_ip": e.src_ip,
            "country_code": e.country_code,
            "country_name": e.country_name,
            "username": e.username,
            "password": e.password,
            "session_id": e.session_id,
            "honeypot_type": e.honeypot_type,
        }
        for e in events
    ]


@app.get("/sessions/by-country/{country_code}", tags=["Interactive"])
def get_sessions_by_country(
    country_code: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list:
    """Récupère les sessions provenant d'un pays spécifique."""
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.country_code == country_code.upper())
        .order_by(SessionModel.start_time.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "session_id": s.session_id,
            "src_ip": s.src_ip,
            "country_code": s.country_code,
            "city": s.city,
            "username": s.username,
            "command_count": s.command_count,
            "danger_score": s.danger_score,
            "danger_level": s.danger_level,
            "attacker_type": s.attacker_type,
            "duration_sec": s.duration_sec,
            "start_time": s.start_time,
            "honeypot_type": s.honeypot_type,
        }
        for s in sessions
    ]


@app.get("/commands/by-category/{category}", tags=["Interactive"])
def get_commands_by_category(
    category: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les commandes d'une catégorie spécifique avec les IPs associées."""
    events = (
        db.query(Event)
        .filter(Event.event_type == "command", Event.command_category == category)
        .order_by(Event.ts_epoch.desc())
        .limit(limit)
        .all()
    )

    # Aggregate by command
    cmd_data = {}
    for e in events:
        cmd = e.command[:100] if e.command else ""
        if cmd not in cmd_data:
            cmd_data[cmd] = {
                "command": cmd,
                "full_command": e.command,
                "severity": e.command_severity,
                "mitre_techniques": e.mitre_techniques or [],
                "count": 0,
                "ips": set(),
            }
        cmd_data[cmd]["count"] += 1
        if e.src_ip:
            cmd_data[cmd]["ips"].add(e.src_ip)

    # Convert to list and sort
    result = []
    for cmd in sorted(cmd_data.values(), key=lambda x: x["count"], reverse=True):
        cmd["ips"] = list(cmd["ips"])[:10]
        cmd["unique_ips"] = len(cmd["ips"])
        result.append(cmd)

    return {
        "category": category,
        "total_commands": len(events),
        "unique_commands": len(cmd_data),
        "commands": result[:30],
    }


@app.get("/commands/by-severity/{severity}", tags=["Interactive"])
def get_commands_by_severity(
    severity: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les commandes d'une sévérité spécifique avec les IPs associées."""
    events = (
        db.query(Event)
        .filter(Event.event_type == "command", Event.command_severity == severity)
        .order_by(Event.ts_epoch.desc())
        .limit(limit)
        .all()
    )

    # Aggregate by command
    cmd_data = {}
    for e in events:
        cmd = e.command[:100] if e.command else ""
        if cmd not in cmd_data:
            cmd_data[cmd] = {
                "command": cmd,
                "full_command": e.command,
                "category": e.command_category,
                "mitre_techniques": e.mitre_techniques or [],
                "count": 0,
                "ips": set(),
            }
        cmd_data[cmd]["count"] += 1
        if e.src_ip:
            cmd_data[cmd]["ips"].add(e.src_ip)

    # Convert to list
    result = []
    for cmd in sorted(cmd_data.values(), key=lambda x: x["count"], reverse=True):
        cmd["ips"] = list(cmd["ips"])[:10]
        cmd["unique_ips"] = len(cmd["ips"])
        result.append(cmd)

    return {
        "severity": severity,
        "total_commands": len(events),
        "unique_commands": len(cmd_data),
        "commands": result[:30],
    }


@app.get("/ips/{ip}/details", tags=["Interactive"])
def get_ip_full_details(
    ip: str,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère tous les détails d'une IP: sessions, commandes, auth, timeline."""
    # Get all sessions for this IP
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.src_ip == ip)
        .order_by(SessionModel.start_time.desc())
        .all()
    )

    # Get all events for this IP
    events = (
        db.query(Event)
        .filter(Event.src_ip == ip)
        .order_by(Event.ts_epoch.desc())
        .limit(200)
        .all()
    )

    # Aggregate commands
    cmd_counts = {}
    for e in events:
        if e.event_type == "command" and e.command:
            cmd = e.command[:80]
            if cmd not in cmd_counts:
                cmd_counts[cmd] = {
                    "command": cmd,
                    "full": e.command,
                    "category": e.command_category,
                    "severity": e.command_severity,
                    "count": 0,
                }
            cmd_counts[cmd]["count"] += 1

    # Auth events
    auth_events = [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "username": e.username,
            "password": e.password,
            "session_id": e.session_id,
        }
        for e in events
        if e.event_type in ("login_success", "login_failed")
    ]

    # First event for geo info
    first_connect = next((e for e in reversed(events) if e.event_type == "connect"), None)

    return {
        "ip": ip,
        "geo": {
            "country_code": first_connect.country_code if first_connect else None,
            "country_name": first_connect.country_name if first_connect else None,
            "city": first_connect.city if first_connect else None,
            "asn_org": first_connect.asn_org if first_connect else None,
        },
        "stats": {
            "total_sessions": len(sessions),
            "total_commands": sum(1 for e in events if e.event_type == "command"),
            "total_auth_attempts": len(auth_events),
            "successful_logins": sum(1 for e in auth_events if e["event_type"] == "login_success"),
            "unique_usernames": len(set(e["username"] for e in auth_events if e["username"])),
            "avg_danger_score": (
                round(sum(s.danger_score or 0 for s in sessions) / len(sessions), 1)
                if sessions
                else 0
            ),
        },
        "danger_distribution": {
            "critical": sum(1 for s in sessions if s.danger_level == "critical"),
            "high": sum(1 for s in sessions if s.danger_level == "high"),
            "medium": sum(1 for s in sessions if s.danger_level == "medium"),
            "low": sum(1 for s in sessions if s.danger_level == "low"),
            "minimal": sum(1 for s in sessions if s.danger_level == "minimal"),
        },
        "sessions": [
            {
                "session_id": s.session_id,
                "username": s.username,
                "command_count": s.command_count,
                "danger_score": s.danger_score,
                "danger_level": s.danger_level,
                "attacker_type": s.attacker_type,
                "duration_sec": s.duration_sec,
                "start_time": s.start_time,
                "honeypot_type": s.honeypot_type,
                "categories_seen": s.categories_seen,
            }
            for s in sessions[:20]
        ],
        "top_commands": sorted(cmd_counts.values(), key=lambda x: x["count"], reverse=True)[:20],
        "auth_events": auth_events[:30],
        "timeline": [
            {
                "timestamp": e.timestamp,
                "ts_epoch": e.ts_epoch,
                "event_type": e.event_type,
                "command": e.command[:60] if e.command else None,
                "username": e.username,
            }
            for e in events[:50]
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes - MITRE
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/mitre/techniques", tags=["MITRE"])
def get_mitre_techniques(
    _hours: int = 24,
    db: Session = Depends(get_db),
) -> dict:
    """Récupère les techniques MITRE observées."""
    from collections import Counter

    # Récupérer toutes les techniques des événements
    events = db.query(Event.mitre_techniques).filter(Event.mitre_techniques.isnot(None)).all()

    technique_counter: Counter = Counter()
    for (techniques,) in events:
        if techniques:
            technique_counter.update(techniques)

    # Enrichir avec les détails MITRE
    results = []
    for tid, count in technique_counter.most_common(20):
        technique = mitre_mapper.get_technique(tid)
        if technique:
            results.append(
                {
                    "technique_id": tid,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "count": count,
                    "url": technique.url,
                }
            )
        else:
            results.append(
                {
                    "technique_id": tid,
                    "technique_name": "Unknown",
                    "tactic": "Unknown",
                    "count": count,
                    "url": None,
                }
            )

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
