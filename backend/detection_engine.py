import argparse
from datetime import datetime, timedelta, timezone
from typing import List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database import SessionLocal
from backend.app.models import Anomaly, AnomalyType, ScanEvent


def detect_rogue_aps_for_event(
    db: Session, event: ScanEvent, window_minutes: int = 30
) -> List[Tuple[AnomalyType, float, str]]:
    """
    Checks if this scan event represents a rogue AP / evil twin relative to
    other scan events for the same SSID at the same location within a time window.
    """
    window_start = event.timestamp - timedelta(minutes=window_minutes)
    window_end = event.timestamp + timedelta(minutes=window_minutes)

    # Fetch neighboring events with same SSID and location within window
    neighbors = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.location_id == event.location_id,
            ScanEvent.ssid == event.ssid,
            ScanEvent.id != event.id,
            ScanEvent.timestamp >= window_start,
            ScanEvent.timestamp <= window_end,
        )
        .all()
    )

    anomalies = []
    seen_different_bssids = set()
    differing_encryptions = set()

    for n in neighbors:
        if n.bssid != event.bssid:
            seen_different_bssids.add(n.bssid)
        if n.encryption_type != event.encryption_type:
            differing_encryptions.add(n.encryption_type)

    if seen_different_bssids:
        # Confidence increases if encryption was also modified/downgraded or signal is unusually high
        confidence = 0.85
        desc = (
            f"SSID '{event.ssid}' observed with multiple distinct BSSIDs "
            f"(e.g., current: {event.bssid} vs seen: {', '.join(list(seen_different_bssids)[:2])}) "
            f"within a {window_minutes}-minute window at this location."
        )

        if differing_encryptions:
            confidence = 0.95
            desc += f" Conflicting encryption schemes detected: {event.encryption_type} vs {', '.join(differing_encryptions)}."

        anomalies.append((AnomalyType.EVIL_TWIN, confidence, desc))

    return anomalies


def detect_arp_spoof_for_event(
    db: Session, event: ScanEvent, window_minutes: int = 30
) -> List[Tuple[AnomalyType, float, str]]:
    """
    Checks if synthetic gateway ARP resolution indicates conflicting IP-to-MAC associations.
    """
    if not event.gateway_ip or not event.gateway_mac:
        return []

    window_start = event.timestamp - timedelta(minutes=window_minutes)
    window_end = event.timestamp + timedelta(minutes=window_minutes)

    # Search for events at the same location claiming the same gateway IP with an alternate MAC
    conflicting_gateway_events = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.location_id == event.location_id,
            ScanEvent.gateway_ip == event.gateway_ip,
            ScanEvent.gateway_mac != event.gateway_mac,
            ScanEvent.id != event.id,
            ScanEvent.timestamp >= window_start,
            ScanEvent.timestamp <= window_end,
        )
        .all()
    )

    if conflicting_gateway_events:
        alt_macs = {e.gateway_mac for e in conflicting_gateway_events}
        confidence = 0.90
        desc = (
            f"Gateway IP '{event.gateway_ip}' associated with conflicting MAC address "
            f"'{event.gateway_mac}' (alternate known MAC: {', '.join(alt_macs)}) "
            f"within a {window_minutes}-minute window — signature of ARP cache poisoning."
        )
        return [(AnomalyType.ARP_SPOOF, confidence, desc)]

    return []


def run_detection_pass(db: Session, window_minutes: int = 30) -> int:
    """
    Processes unscanned ScanEvents (events without existing Anomaly records)
    and logs detected anomalies idempotently. Returns the count of created anomalies.
    """
    # Query all events that have not yet had any anomaly recorded against them
    already_flagged_subquery = db.query(Anomaly.scan_event_id).distinct()
    unflagged_events = (
        db.query(ScanEvent)
        .filter(~ScanEvent.id.in_(already_flagged_subquery))
        .order_by(ScanEvent.timestamp.asc())
        .all()
    )

    new_anomalies: List[Anomaly] = []

    for event in unflagged_events:
        # Run rogue / evil-twin detector
        rogue_findings = detect_rogue_aps_for_event(db, event, window_minutes=window_minutes)
        for anom_type, conf, desc in rogue_findings:
            new_anomalies.append(
                Anomaly(
                    scan_event_id=event.id,
                    anomaly_type=anom_type,
                    confidence_score=conf,
                    description=desc,
                )
            )

        # Run ARP spoof detector
        arp_findings = detect_arp_spoof_for_event(db, event, window_minutes=window_minutes)
        for anom_type, conf, desc in arp_findings:
            new_anomalies.append(
                Anomaly(
                    scan_event_id=event.id,
                    anomaly_type=anom_type,
                    confidence_score=conf,
                    description=desc,
                )
            )

    if new_anomalies:
        db.bulk_save_objects(new_anomalies)
        db.commit()

    return len(new_anomalies)


def main():
    parser = argparse.ArgumentParser(description="WiFiWatch SA — Heuristic Anomaly Detection Pass")
    parser.add_argument("--window", type=int, default=30, help="Sliding window in minutes (default: 30)")
    args = parser.parse_args()

    db: Session = SessionLocal()
    try:
        print(f"Running detection pass with {args.window}-minute window...")
        count = run_detection_pass(db, window_minutes=args.window)
        total_anomalies = db.query(Anomaly).count()
        print(f"Detection pass complete: {count} new anomalies recorded. Total database anomalies: {total_anomalies}.")
    finally:
        db.close()


if __name__ == "__main__":
    main()