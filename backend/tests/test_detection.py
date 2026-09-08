from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
from backend.app.models import Location, LocationType, ScanEvent, Anomaly, AnomalyType
from backend.detection_engine import run_detection_pass


@pytest.fixture
def test_db():
    """Provides an isolated in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def setup_location(test_db):
    loc = Location(
        name="Test Commuter Station",
        type=LocationType.TRAIN_STATION,
        lat=-26.2041,
        lng=28.0473,
    )
    test_db.add(loc)
    test_db.commit()
    test_db.refresh(loc)
    return loc


def test_clean_traffic_yields_no_anomalies(test_db, setup_location):
    base_time = datetime.now(timezone.utc)

    # 3 legitimate events for same SSID with consistent BSSID and Gateway MAC
    for i in range(3):
        test_db.add(
            ScanEvent(
                location_id=setup_location.id,
                timestamp=base_time + timedelta(minutes=i * 5),
                ssid="CleanMetroWiFi",
                bssid="00:11:22:33:44:55",
                encryption_type="WPA2-PSK",
                signal_strength=-65,
                gateway_ip="192.168.1.1",
                gateway_mac="AA:BB:CC:DD:EE:01",
                is_synthetic=True,
            )
        )
    test_db.commit()

    created_count = run_detection_pass(test_db, window_minutes=30)
    assert created_count == 0
    assert test_db.query(Anomaly).count() == 0


def test_evil_twin_detection(test_db, setup_location):
    base_time = datetime.now(timezone.utc)

    # Legitimate event
    legit_event = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time,
        ssid="Station_FreeWiFi",
        bssid="00:11:22:33:44:55",
        encryption_type="WPA2-PSK",
        signal_strength=-68,
        gateway_ip="192.168.1.1",
        gateway_mac="AA:BB:CC:DD:EE:01",
        is_synthetic=True,
    )

    # Rogue evil twin event: same SSID, different BSSID, open encryption 2 mins later
    rogue_event = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time + timedelta(minutes=2),
        ssid="Station_FreeWiFi",
        bssid="DE:AD:BE:EF:00:01",
        encryption_type="Open",
        signal_strength=-45,
        gateway_ip="192.168.1.1",
        gateway_mac="AA:BB:CC:DD:EE:01",
        is_synthetic=True,
    )

    test_db.add_all([legit_event, rogue_event])
    test_db.commit()

    created_count = run_detection_pass(test_db, window_minutes=30)
    assert created_count >= 1

    anomalies = test_db.query(Anomaly).all()
    evil_twin_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.EVIL_TWIN]
    assert len(evil_twin_anomalies) > 0
    assert evil_twin_anomalies[0].confidence_score >= 0.85
    assert "Station_FreeWiFi" in evil_twin_anomalies[0].description


def test_arp_spoof_detection(test_db, setup_location):
    base_time = datetime.now(timezone.utc)

    # Legitimate baseline gateway MAC
    normal_event = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time,
        ssid="Station_FreeWiFi",
        bssid="00:11:22:33:44:55",
        encryption_type="WPA2-PSK",
        signal_strength=-65,
        gateway_ip="192.168.1.1",
        gateway_mac="AA:BB:CC:DD:EE:01",
        is_synthetic=True,
    )

    # Poisoned event: gateway IP mapped to attacker MAC address 5 mins later
    poisoned_event = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time + timedelta(minutes=5),
        ssid="Station_FreeWiFi",
        bssid="00:11:22:33:44:55",
        encryption_type="WPA2-PSK",
        signal_strength=-66,
        gateway_ip="192.168.1.1",
        gateway_mac="FF:EE:DD:CC:BB:AA",
        is_synthetic=True,
    )

    test_db.add_all([normal_event, poisoned_event])
    test_db.commit()

    created_count = run_detection_pass(test_db, window_minutes=30)
    assert created_count >= 1

    arp_anomalies = test_db.query(Anomaly).filter_by(anomaly_type=AnomalyType.ARP_SPOOF).all()
    assert len(arp_anomalies) > 0
    assert arp_anomalies[0].confidence_score >= 0.90
    assert "192.168.1.1" in arp_anomalies[0].description


def test_detection_pass_is_idempotent(test_db, setup_location):
    base_time = datetime.now(timezone.utc)

    event1 = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time,
        ssid="DupSSID",
        bssid="11:11:11:11:11:11",
        encryption_type="Open",
        signal_strength=-60,
        gateway_ip="10.0.0.1",
        gateway_mac="00:11:22:33:44:55",
        is_synthetic=True,
    )
    event2 = ScanEvent(
        location_id=setup_location.id,
        timestamp=base_time + timedelta(minutes=1),
        ssid="DupSSID",
        bssid="22:22:22:22:22:22",
        encryption_type="Open",
        signal_strength=-55,
        gateway_ip="10.0.0.1",
        gateway_mac="00:11:22:33:44:55",
        is_synthetic=True,
    )

    test_db.add_all([event1, event2])
    test_db.commit()

    first_pass_count = run_detection_pass(test_db, window_minutes=30)
    assert first_pass_count > 0

    # Second pass should detect nothing new and create no duplicates
    second_pass_count = run_detection_pass(test_db, window_minutes=30)
    assert second_pass_count == 0