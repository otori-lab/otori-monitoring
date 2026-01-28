from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app.models import Event


def _since_epoch(hours: int = 24) -> float:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.timestamp()

def compute_kpi(db: Session, hours: int = 24) -> dict:
    since = _since_epoch(hours)

    # nombre de sessions (distinct session_id avec connect)
    sessions = db.query(func.count(distinct(Event.session_id))) \
        .filter(Event.ts_epoch >= since) \
        .filter(Event.event_type == "connect") \
        .scalar() or 0

    # durée moyenne des sessions
    avg_duration = db.query(func.avg(Event.duration_sec)) \
        .filter(Event.ts_epoch >= since) \
        .filter(Event.event_type == "closed") \
        .scalar()
    avg_duration = float(avg_duration) if avg_duration else 0.0

    # commandes par session
    commands = db.query(func.count(Event.id)) \
        .filter(Event.ts_epoch >= since) \
        .filter(Event.event_type == "command") \
        .scalar() or 0

    cmds_per_session = (commands / sessions) if sessions else 0.0

    return {
        "classic": {
            "status": "running",
            "sessions": int(sessions),
            "avg_duration_sec": round(avg_duration, 2),
            "avg_commands_per_session": round(cmds_per_session, 2),
        }
    }


def recent_sessions(db: Session, limit: int = 10, hours: int = 24) -> list:
    since = _since_epoch(hours)

    sub = db.query(
        Event.session_id,
        func.max(Event.timestamp).label("last_ts")
    ).filter(Event.timestamp >= since) \
     .group_by(Event.session_id) \
     .subquery()

    rows = db.query(sub.c.session_id, sub.c.last_ts) \
             .order_by(sub.c.last_ts.desc()) \
             .limit(limit) \
             .all()

    out = []
    for sid, ts in rows:
        src_ip = db.query(Event.src_ip)\
        .filter(Event.session_id == sid)\
        .filter(Event.event_type == "connect")\
        .order_by(Event.id.asc())\
        .first()
        src_ip = src_ip[0] if src_ip else None


        cmd = db.query(Event.command) \
            .filter(Event.session_id == sid) \
            .filter(Event.event_type == "command") \
            .order_by(Event.id.desc()) \
            .first()
        cmd = cmd[0] if cmd else None

        dur = db.query(Event.duration_sec) \
            .filter(Event.session_id == sid) \
            .filter(Event.event_type == "closed") \
            .order_by(Event.id.desc()) \
            .first()
        dur = float(dur[0]) if dur and dur[0] else None

        out.append({
            "session_id": sid,
            "src_ip": src_ip,
            "command": cmd,
            "type": "classic",
            "duration_sec": dur,
            "last_ts": ts,
        })

    return out
