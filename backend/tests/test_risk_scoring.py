from datetime import datetime, date, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
from backend.app.models import Location, LocationType, ScanEvent, Anomaly, AnomalyType
from backend.risk_scoring import get_location_risk, get_all_locations_risk


@pytest.fixture
def risk_test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_location_with_no_scans_scores_zero(risk_test_db):
    loc = Location(name="Quiet Depot", type=LocationType.TRAIN_STATION, lat=-26.0, lng=28.0)
    risk_test_db.add(loc)
    risk_test_db.commit()

    today = date.today()
    summary = get_location_risk(risk_test_db, loc.id, today)

    assert summary["score"] == 0.0
    assert summary["label"] == "Low"
    assert summary["metrics"]["total_scans"] == 0


def test_clean_secured_traffic_scores_low(risk_test_db):
    loc = Location(name="Secure Mall", type=LocationType.MALL, lat=-26.1, lng=28.1)
    risk_test_db.add(loc)
    risk_test_db.commit()

    now = datetime.now(timezone.utc)
    for _ in range(5):
        risk_test_db.add(
            ScanEvent(
                location_id=loc.id,
                timestamp=now,
                ssid="SafeEnterpriseWiFi",
                bssid="AA:BB:CC:DD:EE:FF",
                encryption_type="WPA3-SAE",
                signal_strength=-60,
                gateway_ip="192.168.1.1",
                gateway_mac="00:11:22:33:44:55",
                is_synthetic=True,
            )
        )
    risk_test_db.commit()

    summary = get_location_risk(risk_test_db, loc.id, now.date())
    assert summary["score"] < 25.0
    assert summary["label"] == "Low"


def test_high_risk_evil_twin_and_arp_spoof(risk_test_db):
    loc = Location(name="Compromised Hotspot", type=LocationType.TOWNSHIP_HOTSPOT, lat=-26.2, lng=28.2)
    risk_test_db.add(loc)
    risk_test_db.commit()

    now = datetime.now(timezone.utc)

    # Add open scans and critical anomalies
    event1 = ScanEvent(
        location_id=loc.id,
        timestamp=now,
        ssid="Free-Township-WiFi",
        bssid="11:22:33:44:55:66",
        encryption_type="Open",
        signal_strength=-40,
        gateway_ip="10.0.0.1",
        gateway_mac="DE:AD:BE:EF:00:00",
        is_synthetic=True,
    )
    event2 = ScanEvent(
        location_id=loc.id,
        timestamp=now,
        ssid="Free-Township-WiFi",
        bssid="11:22:33:44:55:77",
        encryption_type="Open",
        signal_strength=-42,
        gateway_ip="10.0.0.1",
        gateway_mac="FA:CE:BO:OK:00:00",
        is_synthetic=True,
    )
    risk_test_db.add_all([event1, event2])
    risk_test_db.commit()

    anomaly1 = Anomaly(
        scan_event_id=event1.id,
        anomaly_type=AnomalyType.EVIL_TWIN,
        confidence_score=0.95,
        description="Evil twin detected with mismatched BSSID and open encryption.",
    )
    anomaly2 = Anomaly(
        scan_event_id=event2.id,
        anomaly_type=AnomalyType.ARP_SPOOF,
        confidence_score=0.90,
        description="Gateway MAC conflict detected.",
    )
    risk_test_db.add_all([anomaly1, anomaly2])
    risk_test_db.commit()

    summary = get_location_risk(risk_test_db, loc.id, now.date())
    assert summary["score"] >= 50.0
    assert summary["label"] in ["High", "Severe"]
    assert summary["metrics"]["anomalies_count"] == 2