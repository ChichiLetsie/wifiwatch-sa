from datetime import datetime, date
from typing import List, Optional
from pydantic import BaseModel
from backend.app.models import LocationType, AnomalyType


class LocationResponse(BaseModel):
    id: int
    name: str
    type: LocationType
    lat: Optional[float] = None
    lng: Optional[float] = None

    class Config:
        from_attributes = True


class RiskMetrics(BaseModel):
    total_scans: int
    open_networks: int
    open_ratio: float
    anomalies_count: int
    evil_twins: int
    arp_spoofs: int


class LocationRiskResponse(BaseModel):
    location_id: int
    location_name: str
    type: Optional[str] = None
    date: str
    score: float
    label: str
    explanation: str
    metrics: RiskMetrics


class ScanEventResponse(BaseModel):
    id: int
    location_id: int
    timestamp: datetime
    ssid: str
    bssid: str
    encryption_type: str
    signal_strength: int
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    is_synthetic: bool

    class Config:
        from_attributes = True


class AnomalyResponse(BaseModel):
    id: int
    scan_event_id: int
    anomaly_type: AnomalyType
    confidence_score: float
    description: str

    class Config:
        from_attributes = True