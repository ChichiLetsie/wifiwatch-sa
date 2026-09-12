from datetime import date, datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base, get_db
from backend.app.models import Location, LocationType, ScanEvent, Anomaly, AnomalyType
from backend.app.main import app

# Setup test SQLite DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Seed sample data
    loc = Location(name="Test Mall Durban", type=LocationType.MALL, lat=-29.8587, lng=31.0218)
    db.add(loc)
    db.commit()
    db.refresh(loc)

    now = datetime.now(timezone.utc)
    event = ScanEvent(
        location_id=loc.id,
        timestamp=now,
        ssid="Durban-Guest-WiFi",
        bssid="AA:BB:CC:DD:EE:FF",
        encryption_type="Open",
        signal_strength=-50,
        gateway_ip="192.168.0.1",
        gateway_mac="00:11:22:33:44:55",
        is_synthetic=True,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    anomaly = Anomaly(
        scan_event_id=event.id,
        anomaly_type=AnomalyType.EVIL_TWIN,
        confidence_score=0.92,
        description="Evil twin detected on guest network.",
    )
    db.add(anomaly)
    db.commit()

    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_locations():
    response = client.get("/api/locations")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "Test Mall Durban"
    assert data[0]["type"] == "mall"


def test_location_risk_endpoint():
    # Fetch location ID first
    locs = client.get("/api/locations").json()
    loc_id = locs[0]["id"]

    response = client.get(f"/api/locations/{loc_id}/risk")
    assert response.status_code == 200
    data = response.json()
    assert data["location_id"] == loc_id
    assert "score" in data
    assert "label" in data
    assert "metrics" in data


def test_risk_overview_endpoint():
    response = client.get("/api/risk/overview")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert "score" in data[0]


def test_location_events_and_anomalies():
    locs = client.get("/api/locations").json()
    loc_id = locs[0]["id"]

    # Events endpoint
    events_res = client.get(f"/api/locations/{loc_id}/events")
    assert events_res.status_code == 200
    assert len(events_res.json()) == 1

    # Anomalies endpoint
    anom_res = client.get(f"/api/locations/{loc_id}/anomalies")
    assert anom_res.status_code == 200
    assert len(anom_res.json()) == 1
    assert anom_res.json()[0]["confidence_score"] == 0.92