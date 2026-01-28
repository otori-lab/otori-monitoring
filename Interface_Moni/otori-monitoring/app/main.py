from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Set

from app.db import Base, engine, SessionLocal
from app.models import Event
from app.kpi import compute_kpi, recent_sessions

from datetime import datetime, timezone


Base.metadata.create_all(bind=engine)

app = FastAPI(title="OTORI Monitoring")

app.mount("/static", StaticFiles(directory="app/web"), name="static")


class OtoriEventIn(BaseModel):
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


class WSManager:
    def __init__(self):
        self.clients: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(payload)
            except:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WSManager()


@app.get("/", response_class=HTMLResponse)
def index():
    with open("app/web/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/ingest")
async def ingest(event: OtoriEventIn):
    db = SessionLocal()
    try:
        e = Event(**event.model_dump())
        # Convertit timestamp ISO -> epoch seconds (robuste pour les filtres)
        try:
            ts = event.timestamp.replace("Z", "+00:00")
            e.ts_epoch = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc).timestamp()
        except:
            e.ts_epoch = None
        db.add(e)
        db.commit()

        kpi = compute_kpi(db)
        recent = recent_sessions(db)

        await ws_manager.broadcast({
            "type": "update",
            "kpi": kpi,
            "recent": recent
        })
        return {"ok": True}
    finally:
        db.close()


@app.get("/kpi")
def get_kpi():
    db = SessionLocal()
    try:
        return compute_kpi(db)
    finally:
        db.close()


@app.get("/sessions/recent")
def get_recent():
    db = SessionLocal()
    try:
        return recent_sessions(db)
    finally:
        db.close()


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
