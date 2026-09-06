from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.database import Base


class LocationType(str, PyEnum):
    TRAIN_STATION = "train_station"
    MALL = "mall"
    TOWNSHIP_HOTSPOT = "township_hotspot"
    OTHER = "other"


class AnomalyType(str, PyEnum):
    ROGUE_AP = "rogue_ap"
    ARP_SPOOF = "arp_spoof"
    EVIL_TWIN = "evil_twin"


class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False, unique=True, index=True)
    type = Column(
        Enum(LocationType, native_enum=False, length=30),
        default=LocationType.OTHER,
        nullable=False,
    )
    lat = Column(Float, nullable=True)
    lng = Column(Float, nullable=True)

    scan_events = relationship("ScanEvent", back_populates="location", cascade="all, delete-orphan")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    ssid = Column(String(64), nullable=False, index=True)
    bssid = Column(String(17), nullable=False, index=True)
    encryption_type = Column(String(32), nullable=False)
    signal_strength = Column(Integer, nullable=False)  # dBm, e.g., -65
    is_synthetic = Column(Boolean, default=True, nullable=False)

    location = relationship("Location", back_populates="scan_events")
    anomalies = relationship("Anomaly", back_populates="scan_event", cascade="all, delete-orphan")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    scan_event_id = Column(Integer, ForeignKey("scan_events.id"), nullable=False, index=True)
    anomaly_type = Column(
        Enum(AnomalyType, native_enum=False, length=30),
        nullable=False,
        index=True,
    )
    confidence_score = Column(Float, nullable=False)  # Scale: 0.0 to 1.0
    description = Column(Text, nullable=False)

    scan_event = relationship("ScanEvent", back_populates="anomalies")