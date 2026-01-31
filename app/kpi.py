"""
Module de calcul des KPIs pour Otori Monitoring.
Fournit des statistiques détaillées et analyses avancées.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session as DBSession

from app.models import Event, Session


def _since_epoch(hours: int = 24) -> float:
    """Calcule le timestamp epoch depuis X heures."""
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.timestamp()


def compute_kpi(db: DBSession, hours: int = 24) -> dict:
    """
    Calcule les KPIs principaux.

    Args:
        db: Session SQLAlchemy.
        hours: Fenêtre de temps en heures.

    Returns:
        Dictionnaire avec tous les KPIs.
    """
    since = _since_epoch(hours)

    # ═══════════════════════════════════════════════════════════════════════════
    # KPIs de base
    # ═══════════════════════════════════════════════════════════════════════════
    base_kpis = _compute_base_kpis(db, since)

    # ═══════════════════════════════════════════════════════════════════════════
    # KPIs géographiques
    # ═══════════════════════════════════════════════════════════════════════════
    geo_kpis = _compute_geo_kpis(db, since)

    # ═══════════════════════════════════════════════════════════════════════════
    # KPIs de classification
    # ═══════════════════════════════════════════════════════════════════════════
    classification_kpis = _compute_classification_kpis(db, since)

    # ═══════════════════════════════════════════════════════════════════════════
    # KPIs de sessions (depuis la table Session si disponible)
    # ═══════════════════════════════════════════════════════════════════════════
    session_kpis = _compute_session_kpis(db, since)

    # ═══════════════════════════════════════════════════════════════════════════
    # Top listes
    # ═══════════════════════════════════════════════════════════════════════════
    top_lists = _compute_top_lists(db, since)

    # ═══════════════════════════════════════════════════════════════════════════
    # Timelines
    # ═══════════════════════════════════════════════════════════════════════════
    timelines = _compute_timelines(db, hours, since)

    # Fusionner tous les KPIs
    return {
        **base_kpis,
        **geo_kpis,
        **classification_kpis,
        **session_kpis,
        **top_lists,
        **timelines,
    }


def _compute_base_kpis(db: DBSession, since: float) -> dict:
    """Calcule les KPIs de base."""
    # Total sessions (distinct session_id with connect)
    total_sessions = (
        db.query(func.count(distinct(Event.session_id)))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .scalar()
        or 0
    )

    # Unique IPs
    unique_ips = (
        db.query(func.count(distinct(Event.src_ip)))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .scalar()
        or 0
    )

    # Average session duration
    avg_duration = (
        db.query(func.avg(Event.duration_sec))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "closed")
        .scalar()
    )
    avg_duration = round(float(avg_duration), 1) if avg_duration else 0.0

    # Total commands
    total_commands = (
        db.query(func.count(Event.id))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .scalar()
        or 0
    )

    # Commands per session
    cmds_per_session = (
        round(total_commands / total_sessions, 1) if total_sessions else 0.0
    )

    # Login attempts
    login_success = (
        db.query(func.count(Event.id))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "login_success")
        .scalar()
        or 0
    )

    login_failed = (
        db.query(func.count(Event.id))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "login_failed")
        .scalar()
        or 0
    )

    total_logins = login_success + login_failed
    login_success_rate = (
        round((login_success / total_logins) * 100, 1) if total_logins else 0.0
    )

    # Unique usernames tried
    unique_usernames = (
        db.query(func.count(distinct(Event.username)))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type.in_(["login_success", "login_failed"]))
        .filter(Event.username.isnot(None))
        .scalar()
        or 0
    )

    # Unique passwords tried
    unique_passwords = (
        db.query(func.count(distinct(Event.password)))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type.in_(["login_success", "login_failed"]))
        .filter(Event.password.isnot(None))
        .scalar()
        or 0
    )

    return {
        "total_sessions": total_sessions,
        "unique_ips": unique_ips,
        "avg_duration_sec": avg_duration,
        "total_commands": total_commands,
        "cmds_per_session": cmds_per_session,
        "login_success": login_success,
        "login_failed": login_failed,
        "login_success_rate": login_success_rate,
        "unique_usernames": unique_usernames,
        "unique_passwords": unique_passwords,
    }


def _compute_geo_kpis(db: DBSession, since: float) -> dict:
    """Calcule les KPIs géographiques."""
    # Unique countries
    unique_countries = (
        db.query(func.count(distinct(Event.country_code)))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .filter(Event.country_code.isnot(None))
        .filter(Event.country_code != "PRIVATE")
        .scalar()
        or 0
    )

    # Top countries
    top_countries = (
        db.query(
            Event.country_code,
            Event.country_name,
            func.count(distinct(Event.session_id)).label("sessions"),
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .filter(Event.country_code.isnot(None))
        .filter(Event.country_code != "PRIVATE")
        .group_by(Event.country_code, Event.country_name)
        .order_by(func.count(distinct(Event.session_id)).desc())
        .limit(10)
        .all()
    )
    top_countries = [
        {"code": c, "name": n or c, "sessions": s} for c, n, s in top_countries
    ]

    # Top ASN organizations
    top_asn = (
        db.query(
            Event.asn_org,
            func.count(distinct(Event.session_id)).label("sessions"),
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .filter(Event.asn_org.isnot(None))
        .group_by(Event.asn_org)
        .order_by(func.count(distinct(Event.session_id)).desc())
        .limit(10)
        .all()
    )
    top_asn = [{"org": org, "sessions": s} for org, s in top_asn]

    # Coordonnées pour la carte (sample des attaques récentes)
    attack_coordinates = (
        db.query(
            Event.src_ip,
            Event.latitude,
            Event.longitude,
            Event.country_code,
            Event.city,
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .filter(Event.latitude.isnot(None))
        .filter(Event.longitude.isnot(None))
        .order_by(Event.ts_epoch.desc())
        .limit(100)
        .all()
    )
    attack_coordinates = [
        {"ip": ip, "lat": lat, "lon": lon, "country": cc, "city": city}
        for ip, lat, lon, cc, city in attack_coordinates
    ]

    return {
        "unique_countries": unique_countries,
        "top_countries": top_countries,
        "top_asn": top_asn,
        "attack_coordinates": attack_coordinates,
    }


def _compute_classification_kpis(db: DBSession, since: float) -> dict:
    """Calcule les KPIs de classification des commandes."""
    # Distribution par catégorie
    category_dist = (
        db.query(
            Event.command_category,
            func.count(Event.id).label("count"),
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command_category.isnot(None))
        .group_by(Event.command_category)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    category_distribution = [{"category": c, "count": cnt} for c, cnt in category_dist]

    # Distribution par sévérité
    severity_dist = (
        db.query(
            Event.command_severity,
            func.count(Event.id).label("count"),
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command_severity.isnot(None))
        .group_by(Event.command_severity)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    severity_distribution = [{"severity": s, "count": cnt} for s, cnt in severity_dist]

    # Commandes critiques
    critical_commands = (
        db.query(func.count(Event.id))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command_severity == "critical")
        .scalar()
        or 0
    )

    high_commands = (
        db.query(func.count(Event.id))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command_severity == "high")
        .scalar()
        or 0
    )

    return {
        "category_distribution": category_distribution,
        "severity_distribution": severity_distribution,
        "critical_commands": critical_commands,
        "high_commands": high_commands,
    }


def _compute_session_kpis(db: DBSession, since: float) -> dict:
    """Calcule les KPIs depuis la table Session."""
    try:
        # Distribution par niveau de danger
        danger_dist = (
            db.query(
                Session.danger_level,
                func.count(Session.id).label("count"),
            )
            .filter(Session.start_time >= since)
            .group_by(Session.danger_level)
            .all()
        )
        danger_distribution = [
            {"level": level, "count": cnt} for level, cnt in danger_dist
        ]

        # Compteurs par danger
        sessions_critical = sum(
            cnt for level, cnt in danger_dist if level == "critical"
        )
        sessions_high = sum(cnt for level, cnt in danger_dist if level == "high")
        sessions_medium = sum(cnt for level, cnt in danger_dist if level == "medium")

        # Distribution par type d'attaquant
        attacker_dist = (
            db.query(
                Session.attacker_type,
                func.count(Session.id).label("count"),
            )
            .filter(Session.start_time >= since)
            .group_by(Session.attacker_type)
            .all()
        )
        attacker_distribution = [
            {"type": t, "count": cnt} for t, cnt in attacker_dist
        ]

        # Bot ratio
        total_typed = sum(cnt for _, cnt in attacker_dist)
        bots = sum(cnt for t, cnt in attacker_dist if t == "bot")
        bot_ratio = round((bots / total_typed) * 100, 1) if total_typed else 0.0

        # Sessions avec persistence
        sessions_with_persistence = (
            db.query(func.count(Session.id))
            .filter(Session.start_time >= since)
            .filter(Session.has_persistence == True)
            .scalar()
            or 0
        )

        # Sessions avec exfiltration
        sessions_with_exfil = (
            db.query(func.count(Session.id))
            .filter(Session.start_time >= since)
            .filter(Session.has_exfiltration == True)
            .scalar()
            or 0
        )

        # Average danger score
        avg_danger = (
            db.query(func.avg(Session.danger_score))
            .filter(Session.start_time >= since)
            .scalar()
        )
        avg_danger_score = round(float(avg_danger), 1) if avg_danger else 0.0

        # Top MITRE techniques (agrégé depuis les sessions)
        # On récupère les sessions et on compte les techniques
        sessions_with_mitre = (
            db.query(Session.mitre_techniques)
            .filter(Session.start_time >= since)
            .filter(Session.mitre_techniques.isnot(None))
            .all()
        )

        technique_counter: Counter = Counter()
        for (techniques,) in sessions_with_mitre:
            if techniques:
                technique_counter.update(techniques)

        top_mitre_techniques = [
            {"technique": t, "count": c}
            for t, c in technique_counter.most_common(10)
        ]

        return {
            "danger_distribution": danger_distribution,
            "sessions_critical": sessions_critical,
            "sessions_high": sessions_high,
            "sessions_medium": sessions_medium,
            "attacker_distribution": attacker_distribution,
            "bot_ratio": bot_ratio,
            "sessions_with_persistence": sessions_with_persistence,
            "sessions_with_exfil": sessions_with_exfil,
            "avg_danger_score": avg_danger_score,
            "top_mitre_techniques": top_mitre_techniques,
        }
    except Exception:
        # Table Session n'existe pas encore ou autre erreur
        return {
            "danger_distribution": [],
            "sessions_critical": 0,
            "sessions_high": 0,
            "sessions_medium": 0,
            "attacker_distribution": [],
            "bot_ratio": 0.0,
            "sessions_with_persistence": 0,
            "sessions_with_exfil": 0,
            "avg_danger_score": 0.0,
            "top_mitre_techniques": [],
        }


def _compute_top_lists(db: DBSession, since: float) -> dict:
    """Calcule les top listes."""
    # Top 10 IPs
    top_ips = (
        db.query(Event.src_ip, func.count(Event.id).label("count"))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "connect")
        .filter(Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_ips = [{"ip": ip, "count": count} for ip, count in top_ips]

    # Top 10 usernames
    top_usernames = (
        db.query(Event.username, func.count(Event.id).label("count"))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type.in_(["login_success", "login_failed"]))
        .filter(Event.username.isnot(None))
        .group_by(Event.username)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_usernames = [{"username": u, "count": c} for u, c in top_usernames]

    # Top 10 passwords
    top_passwords = (
        db.query(Event.password, func.count(Event.id).label("count"))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type.in_(["login_success", "login_failed"]))
        .filter(Event.password.isnot(None))
        .filter(Event.password != "")
        .group_by(Event.password)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_passwords = [{"password": p, "count": c} for p, c in top_passwords]

    # Top 10 commands
    top_commands = (
        db.query(Event.command, func.count(Event.id).label("count"))
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command.isnot(None))
        .group_by(Event.command)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_commands = [{"command": cmd, "count": c} for cmd, c in top_commands]

    # Top dangerous commands (critical + high severity)
    top_dangerous_commands = (
        db.query(
            Event.command,
            Event.command_category,
            Event.command_severity,
            func.count(Event.id).label("count"),
        )
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == "command")
        .filter(Event.command_severity.in_(["critical", "high"]))
        .group_by(Event.command, Event.command_category, Event.command_severity)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_dangerous_commands = [
        {"command": cmd, "category": cat, "severity": sev, "count": c}
        for cmd, cat, sev, c in top_dangerous_commands
    ]

    return {
        "top_ips": top_ips,
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "top_commands": top_commands,
        "top_dangerous_commands": top_dangerous_commands,
    }


def _compute_timelines(db: DBSession, hours: int, since: float) -> dict:
    """Calcule les timelines."""
    sessions_timeline = _get_timeline(db, hours, since, "connect")
    commands_timeline = _get_timeline(db, hours, since, "command")
    logins_timeline = _get_timeline(db, hours, since, "login_failed")

    return {
        "sessions_timeline": sessions_timeline,
        "commands_timeline": commands_timeline,
        "logins_timeline": logins_timeline,
    }


def _get_timeline(
    db: DBSession, hours: int, since: float, event_type: str
) -> list[dict]:
    """Génère une timeline horaire."""
    now = datetime.now(timezone.utc)

    # Build empty timeline
    timeline = {}
    for i in range(hours, -1, -1):
        dt = now - timedelta(hours=i)
        hour_key = dt.strftime("%Y-%m-%d %H:00")
        label = dt.strftime("%Hh")
        timeline[hour_key] = {"label": label, "hour": hour_key, "count": 0}

    # Query events
    events = (
        db.query(Event.ts_epoch)
        .filter(Event.ts_epoch >= since)
        .filter(Event.event_type == event_type)
        .filter(Event.ts_epoch.isnot(None))
        .all()
    )

    # Count per hour
    for (ts,) in events:
        if ts:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            hour_key = dt.strftime("%Y-%m-%d %H:00")
            if hour_key in timeline:
                timeline[hour_key]["count"] += 1

    return list(timeline.values())


def recent_sessions(db: DBSession, limit: int = 10, hours: int = 24) -> list[dict]:
    """
    Récupère les sessions récentes avec leurs analyses.

    Args:
        db: Session SQLAlchemy.
        limit: Nombre max de sessions.
        hours: Fenêtre de temps.

    Returns:
        Liste des sessions avec détails.
    """
    since = _since_epoch(hours)

    # D'abord essayer depuis la table Session
    try:
        sessions = (
            db.query(Session)
            .filter(Session.start_time >= since)
            .order_by(Session.start_time.desc())
            .limit(limit)
            .all()
        )

        if sessions:
            return [
                {
                    "session_id": s.session_id,
                    "src_ip": s.src_ip,
                    "country_code": s.country_code,
                    "country_name": s.country_name,
                    "city": s.city,
                    "username": s.username,
                    "command_count": s.command_count,
                    "danger_score": s.danger_score,
                    "danger_level": s.danger_level,
                    "attacker_type": s.attacker_type,
                    "has_persistence": s.has_persistence,
                    "has_credential_access": s.has_credential_access,
                    "mitre_techniques": s.mitre_techniques or [],
                    "attack_phase": s.attack_phase,
                    "duration_sec": s.duration_sec,
                    "start_time": s.start_time,
                    "honeypot_type": s.honeypot_type,
                }
                for s in sessions
            ]
    except Exception:
        pass

    # Fallback: construire depuis les events
    return _recent_sessions_from_events(db, limit, since)


def _recent_sessions_from_events(
    db: DBSession, limit: int, since: float
) -> list[dict]:
    """Construit les sessions récentes depuis la table Event."""
    # Get recent sessions by last activity
    sub = (
        db.query(Event.session_id, func.max(Event.ts_epoch).label("last_ts"))
        .filter(Event.ts_epoch >= since)
        .group_by(Event.session_id)
        .subquery()
    )

    rows = (
        db.query(sub.c.session_id, sub.c.last_ts)
        .order_by(sub.c.last_ts.desc())
        .limit(limit)
        .all()
    )

    if not rows:
        return []

    session_ids = [sid for sid, _ in rows]

    # Batch fetch all events for these sessions
    all_events = db.query(Event).filter(Event.session_id.in_(session_ids)).all()

    # Group by session
    sessions_data = {}
    for e in all_events:
        if e.session_id not in sessions_data:
            sessions_data[e.session_id] = {
                "src_ip": None,
                "country_code": None,
                "country_name": None,
                "city": None,
                "username": None,
                "command_count": 0,
                "last_command": None,
                "duration_sec": None,
                "honeypot_type": "unknown",
                "commands": [],
            }

        sd = sessions_data[e.session_id]

        if e.event_type == "connect" and e.src_ip:
            sd["src_ip"] = e.src_ip
            sd["country_code"] = e.country_code
            sd["country_name"] = e.country_name
            sd["city"] = e.city

        if e.event_type in ["login_success", "login_failed"] and e.username:
            sd["username"] = e.username

        if e.event_type == "command":
            sd["command_count"] += 1
            sd["last_command"] = e.command
            if e.command:
                sd["commands"].append(e.command)

        if e.event_type == "closed" and e.duration_sec:
            sd["duration_sec"] = float(e.duration_sec)

        if e.honeypot_type:
            sd["honeypot_type"] = e.honeypot_type

    # Build result in order
    out = []
    for sid, ts in rows:
        if sid in sessions_data:
            sd = sessions_data[sid]
            out.append(
                {
                    "session_id": sid,
                    "src_ip": sd["src_ip"],
                    "country_code": sd["country_code"],
                    "country_name": sd["country_name"],
                    "city": sd["city"],
                    "username": sd["username"],
                    "command_count": sd["command_count"],
                    "last_command": sd["last_command"],
                    "honeypot_type": sd["honeypot_type"],
                    "duration_sec": sd["duration_sec"],
                    "last_ts": ts,
                    # Pas de scoring sans la table Session
                    "danger_score": 0,
                    "danger_level": "unknown",
                    "attacker_type": "unknown",
                }
            )

    return out


def get_attack_summary(db: DBSession, hours: int = 24) -> dict:
    """
    Génère un résumé exécutif des attaques.

    Args:
        db: Session SQLAlchemy.
        hours: Fenêtre de temps.

    Returns:
        Résumé structuré.
    """
    kpis = compute_kpi(db, hours)

    # Calculer le threat level global
    threat_level = "low"
    if kpis.get("sessions_critical", 0) > 0:
        threat_level = "critical"
    elif kpis.get("sessions_high", 0) > 5:
        threat_level = "high"
    elif kpis.get("sessions_medium", 0) > 10:
        threat_level = "medium"

    return {
        "threat_level": threat_level,
        "summary": {
            "total_attacks": kpis["total_sessions"],
            "unique_attackers": kpis["unique_ips"],
            "countries_involved": kpis.get("unique_countries", 0),
            "critical_sessions": kpis.get("sessions_critical", 0),
            "commands_executed": kpis["total_commands"],
            "bot_percentage": kpis.get("bot_ratio", 0),
        },
        "top_threat": (
            kpis["top_countries"][0] if kpis.get("top_countries") else None
        ),
        "most_dangerous_command": (
            kpis["top_dangerous_commands"][0]
            if kpis.get("top_dangerous_commands")
            else None
        ),
        "period_hours": hours,
    }
