from typing import Any, Dict, Optional

def map_cowrie_to_otori(c: Dict[str, Any], sensor_default: str = "otori-local") -> Optional[Dict[str, Any]]:
    """
    Transforme un event Cowrie (raw JSON) en event OTORI (format unifié).
    Retourne None si l'event n'est pas utile en V1.
    """
    eventid = c.get("eventid")
    if not eventid:
        return None

    session_id = c.get("session")
    ts = c.get("timestamp")
    sensor = c.get("sensor", sensor_default)

    src_ip = c.get("src_ip")
    src_port = c.get("src_port")
    dst_ip = c.get("dst_ip")
    dst_port = c.get("dst_port")
    protocol = c.get("protocol")

    # --- mapping eventid -> event_type ---
    if eventid == "cowrie.session.connect":
        event_type = "connect"
        username = password = command = None
        duration = None

    elif eventid == "cowrie.login.failed":
        event_type = "login_failed"
        username = c.get("username")
        password = c.get("password")
        command = None
        duration = None

    elif eventid == "cowrie.login.success":
        event_type = "login_success"
        username = c.get("username")
        password = c.get("password")
        command = None
        duration = None

    elif eventid == "cowrie.command.input":
        event_type = "command"
        username = password = None
        command = c.get("input")
        duration = None

    elif eventid == "cowrie.session.file_download":
        event_type = "download"
        username = password = None
        command = None
        duration = None

    elif eventid == "cowrie.session.closed":
        event_type = "closed"
        username = password = command = None
        try:
            duration = float(c.get("duration")) if c.get("duration") is not None else None
        except:
            duration = None

    else:
        # on ignore les eventid non nécessaires en V1
        return None

    return {
        "timestamp": ts,
        "sensor": sensor,
        "honeypot_type": "classic",
        "session_id": session_id,

        "src_ip": src_ip,
        "src_port": int(src_port) if src_port is not None else None,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port is not None else None,
        "protocol": protocol,

        "event_type": event_type,
        "username": username,
        "password": password,
        "command": command,
        "duration_sec": duration,
    }
