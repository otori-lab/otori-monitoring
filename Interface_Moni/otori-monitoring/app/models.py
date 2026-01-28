from sqlalchemy import Column, Integer, String, Float
from app.db import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    # --- Champs OTORI ---
    timestamp = Column(String, index=True)      # ISO 8601
    sensor = Column(String, index=True)
    honeypot_type = Column(String, index=True)  # classic / ia
    session_id = Column(String, index=True)

    src_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)

    event_type = Column(String, index=True)     # connect / command / login / closed...
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    command = Column(String, nullable=True)

    duration_sec = Column(Float, nullable=True)
    ts_epoch = Column(Float, index=True)  # timestamp en secondes (UTC)

