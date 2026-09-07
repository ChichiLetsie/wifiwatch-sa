import argparse
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple
from sqlalchemy.orm import Session

from backend.app.database import SessionLocal, engine, Base
from backend.app.models import Location, LocationType, ScanEvent

# 6 Fictional South African Locations across all 4 LocationType enums
FICTIONAL_LOCATIONS = [
    {
        "name": "Thembisa Central Hub Wi-Fi",
        "type": LocationType.TOWNSHIP_HOTSPOT,
        "lat": -25.9964,
        "lng": 28.2268,
        "networks": [
            {
                "ssid": "Thembisa-Free-Gov-WiFi",
                "bssid": "02:1A:11:AA:01:01",
                "encryption": "Open",
                "gw_ip": "10.10.0.1",
                "gw_mac": "00:0F:33:01:AA:11",
                "base_signal": -68,
            },
            {
                "ssid": "Ikasi-Connect-Zone",
                "bssid": "02:1A:11:BB:02:02",
                "encryption": "WPA2-PSK",
                "gw_ip": "192.168.10.1",
                "gw_mac": "00:0F:33:02:BB:22",
                "base_signal": -72,
            },
        ],
    },
    {
        "name": "Khayelitsha Site C Interchange",
        "type": LocationType.TOWNSHIP_HOTSPOT,
        "lat": -34.0205,
        "lng": 18.6651,
        "networks": [
            {
                "ssid": "SiteC-Commuter-WiFi",
                "bssid": "02:2B:22:11:03:01",
                "encryption": "Open",
                "gw_ip": "10.20.0.1",
                "gw_mac": "00:0E:44:03:CC:33",
                "base_signal": -64,
            },
            {
                "ssid": "SmartCape-Library-Hotspot",
                "bssid": "02:2B:22:22:03:02",
                "encryption": "WPA2-Enterprise",
                "gw_ip": "172.16.5.1",
                "gw_mac": "00:0E:44:04:DD:44",
                "base_signal": -75,
            },
        ],
    },
    {
        "name": "Protea Glen Commuter Terminal",
        "type": LocationType.TRAIN_STATION,
        "lat": -26.2842,
        "lng": 27.8184,
        "networks": [
            {
                "ssid": "MetroRail-Public-Free",
                "bssid": "02:3C:33:01:04:01",
                "encryption": "Open",
                "gw_ip": "192.168.1.1",
                "gw_mac": "00:0D:55:05:EE:55",
                "base_signal": -62,
            },
            {
                "ssid": "Station-Staff-Secure",
                "bssid": "02:3C:33:02:04:02",
                "encryption": "WPA3-SAE",
                "gw_ip": "192.168.100.1",
                "gw_mac": "00:0D:55:06:FF:66",
                "base_signal": -58,
            },
        ],
    },
    {
        "name": "Umhlanga Promenade Rail Junction",
        "type": LocationType.TRAIN_STATION,
        "lat": -29.7289,
        "lng": 31.0841,
        "networks": [
            {
                "ssid": "ExpressTrain-Passenger-WiFi",
                "bssid": "02:4D:44:01:05:01",
                "encryption": "WPA2-PSK",
                "gw_ip": "10.30.1.1",
                "gw_mac": "00:0C:66:07:AA:77",
                "base_signal": -60,
            }
        ],
    },
    {
        "name": "Jacaranda Ridge Promenade Mall",
        "type": LocationType.MALL,
        "lat": -25.7511,
        "lng": 28.2415,
        "networks": [
            {
                "ssid": "Jacaranda-Guest-Connect",
                "bssid": "02:5E:55:01:06:01",
                "encryption": "Open",
                "gw_ip": "172.20.1.1",
                "gw_mac": "00:0B:77:08:BB:88",
                "base_signal": -55,
            },
            {
                "ssid": "Mugg&Bean-Customer-WiFi",
                "bssid": "02:5E:55:02:06:02",
                "encryption": "WPA2-PSK",
                "gw_ip": "192.168.0.1",
                "gw_mac": "00:0B:77:09:CC:99",
                "base_signal": -69,
            },
        ],
    },
    {
        "name": "Mangaung Civic Precinct",
        "type": LocationType.OTHER,
        "lat": -29.1211,
        "lng": 26.2144,
        "networks": [
            {
                "ssid": "FreeState-Civic-Open",
                "bssid": "02:6F:66:01:07:01",
                "encryption": "Open",
                "gw_ip": "10.50.0.1",
                "gw_mac": "00:0A:88:10:DD:00",
                "base_signal": -70,
            }
        ],
    },
]


def random_mac() -> str:
    """Generates a locally administered unicast MAC address."""
    return f"02:{random.randint(16, 255):02X}:{random.randint(16, 255):02X}:{random.randint(16, 255):02X}:{random.randint(16, 255):02X}:{random.randint(16, 255):02X}"


def get_or_create_locations(db: Session) -> Dict[str, Location]:
    """Ensures the 6 reference locations exist in SQLite."""
    loc_map = {}
    for loc_data in FICTIONAL_LOCATIONS:
        loc = db.query(Location).filter_by(name=loc_data["name"]).first()
        if not loc:
            loc = Location(
                name=loc_data["name"],
                type=loc_data["type"],
                lat=loc_data["lat"],
                lng=loc_data["lng"],
            )
            db.add(loc)
            db.commit()
            db.refresh(loc)
        loc_map[loc_data["name"]] = loc
    return loc_map


def generate_synthetic_dataset(
    db: Session,
    days: int = 7,
    events_per_day: int = 200,
    rogue_ratio: float = 0.05,
    arp_spoof_ratio: float = 0.05,
):
    """
    Generates a deterministic yet varied synthetic timeline of scan events.
    Injects realistic normal traffic along with Evil Twin and ARP Poisoning patterns.
    """
    loc_map = get_or_create_locations(db)
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days)
    total_events = days * events_per_day

    # Pre-generate target timestamps spaced across the requested window
    interval_seconds = int((days * 86400) / max(total_events, 1))

    created_events = []
    current_time = start_time

    for _ in range(total_events):
        current_time += timedelta(seconds=random.randint(max(1, interval_seconds - 20), interval_seconds + 20))
        if current_time > now:
            break

        loc_spec = random.choice(FICTIONAL_LOCATIONS)
        loc_record = loc_map[loc_spec["name"]]
        legit_net = random.choice(loc_spec["networks"])

        roll = random.random()

        # 1. ROGUE AP / EVIL TWIN PATTERN
        if roll < rogue_ratio:
            # Same SSID, rogue/different BSSID, often higher signal (attacker sits closer) or downgrade encryption
            rogue_bssid = random_mac()
            # Often attackers clone open networks or strip encryption
            encryption = "Open" if legit_net["encryption"] != "Open" and random.random() < 0.5 else legit_net["encryption"]
            # Signal is often unnaturally strong (-42 to -55 dBm) because the rogue AP is on the user's immediate perimeter
            signal = random.randint(-55, -38)

            event = ScanEvent(
                location_id=loc_record.id,
                timestamp=current_time,
                ssid=legit_net["ssid"],
                bssid=rogue_bssid,
                encryption_type=encryption,
                signal_strength=signal,
                gateway_ip=legit_net["gw_ip"],
                gateway_mac=legit_net["gw_mac"],
                is_synthetic=True,
            )

        # 2. ARP SPOOFING PATTERN
        elif roll < (rogue_ratio + arp_spoof_ratio):
            # Normal SSID and BSSID, but the gateway MAC has been poisoned to an attacker MAC
            attacker_gw_mac = random_mac()
            signal = legit_net["base_signal"] + random.randint(-6, 6)

            event = ScanEvent(
                location_id=loc_record.id,
                timestamp=current_time,
                ssid=legit_net["ssid"],
                bssid=legit_net["bssid"],
                encryption_type=legit_net["encryption"],
                signal_strength=signal,
                gateway_ip=legit_net["gw_ip"],
                gateway_mac=attacker_gw_mac,  # Inconsistent MAC claim for gateway IP
                is_synthetic=True,
            )

        # 3. NORMAL TRAFFIC PATTERN
        else:
            signal = legit_net["base_signal"] + random.randint(-8, 8)
            event = ScanEvent(
                location_id=loc_record.id,
                timestamp=current_time,
                ssid=legit_net["ssid"],
                bssid=legit_net["bssid"],
                encryption_type=legit_net["encryption"],
                signal_strength=signal,
                gateway_ip=legit_net["gw_ip"],
                gateway_mac=legit_net["gw_mac"],
                is_synthetic=True,
            )

        created_events.append(event)

        # Commit in batches of 500
        if len(created_events) >= 500:
            db.bulk_save_objects(created_events)
            db.commit()
            created_events.clear()

    if created_events:
        db.bulk_save_objects(created_events)
        db.commit()

    total_inserted = db.query(ScanEvent).filter(ScanEvent.is_synthetic == True).count()
    print(f"Synthetic simulation complete: database currently holds {total_inserted} synthetic scan events.")


def main():
    parser = argparse.ArgumentParser(description="WiFiWatch SA — Synthetic Scan Data Generator")
    parser.add_argument("--days", type=int, default=7, help="Number of past days to simulate (default: 7)")
    parser.add_argument("--events-per-day", type=int, default=200, help="Scan events generated per day (default: 200)")
    parser.add_argument("--rogue-rate", type=float, default=0.05, help="Ratio of Rogue AP/Evil Twin attacks (default: 0.05)")
    parser.add_argument("--arp-rate", type=float, default=0.05, help="Ratio of ARP spoof anomalies (default: 0.05)")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        print(f"Generating synthetic Wi-Fi telemetry: {args.days} days, {args.events_per_day} events/day...")
        generate_synthetic_dataset(
            db=db,
            days=args.days,
            events_per_day=args.events_per_day,
            rogue_ratio=args.rogue_rate,
            arp_spoof_ratio=args.arp_rate,
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()