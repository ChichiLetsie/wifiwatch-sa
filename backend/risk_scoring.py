from datetime import datetime, date, timezone
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database import SessionLocal
from backend.app.models import Location, ScanEvent, Anomaly, AnomalyType


def score_to_label(score: float) -> tuple[str, str]:
    """
    Maps a 0-100 numeric risk score to a plain-language tier and educational explanation.
    """
    if score >= 75:
        return (
            "Severe",
            "Critical risk detected: Multiple active rogue access points or spoofed gateways present serious interception hazards."
        )
    elif score >= 50:
        return (
            "High",
            "Elevated risk: Unusual wireless activity or suspicious BSSID variations suggest active network monitoring."
        )
    elif score >= 25:
        return (
            "Moderate",
            "Moderate risk: Some unsecured open networks or minor environmental inconsistencies observed."
        )
    else:
        return (
            "Low",
            "Normal conditions: Monitored access points show consistent hardware and cryptographic signatures."
        )


def get_location_risk(db: Session, location_id: int, target_date: date) -> Dict[str, Any]:
    """
    Computes the risk score and metrics for a specific location on a given date.
    """
    location = db.query(Location).filter(Location.id == location_id).first()
    if not location:
        return {"error": "Location not found"}

    # Define date range (UTC start to end of day)
    start_dt = datetime.combine(target_date, datetime.min.time(), tzinfo=timezone.utc)
    end_dt = datetime.combine(target_date, datetime.max.time(), tzinfo=timezone.utc)

    # Fetch scan events for this location on target date
    scans = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.location_id == location_id,
            ScanEvent.timestamp >= start_dt,
            ScanEvent.timestamp <= end_dt,
        )
        .all()
    )

    total_scans = len(scans)
    if total_scans == 0:
        return {
            "location_id": location.id,
            "location_name": location.name,
            "date": target_date.isoformat(),
            "score": 0.0,
            "label": "Low",
            "explanation": "No scan data recorded for this date.",
            "metrics": {"total_scans": 0, "open_networks": 0, "anomalies_count": 0},
        }

    # Count open networks vs secured
    open_count = sum(1 for s in scans if s.encryption_type.lower() == "open")
    open_ratio = open_count / total_scans

    # Fetch associated anomalies for these scans
    scan_ids = [s.id for s in scans]
    anomalies = (
        db.query(Anomaly)
        .filter(Anomaly.scan_event_id.in_(scan_ids))
        .all()
    )

    anomaly_count = len(anomalies)

    # Compute weighted penalty from anomalies (confidence * severity multiplier)
    anomaly_penalty_sum = 0.0
    type_counts = {AnomalyType.EVIL_TWIN: 0, AnomalyType.ROGUE_AP: 0, AnomalyType.ARP_SPOOF: 0}

    for a in anomalies:
        if a.anomaly_type in type_counts:
            type_counts[a.anomaly_type] += 1
        
        multiplier = 25.0 if a.anomaly_type in (AnomalyType.EVIL_TWIN, AnomalyType.ARP_SPOOF) else 15.0
        anomaly_penalty_sum += (a.confidence_score * multiplier)

    # Baseline open network penalty (up to 25 points if 100% of scans are open)
    open_penalty = open_ratio * 25.0

    # Total score calculation capped at 100
    raw_score = open_penalty + anomaly_penalty_sum
    score = round(min(100.0, max(0.0, raw_score)), 1)

    label, explanation = score_to_label(score)

    return {
        "location_id": location.id,
        "location_name": location.name,
        "type": location.type.value,
        "date": target_date.isoformat(),
        "score": score,
        "label": label,
        "explanation": explanation,
        "metrics": {
            "total_scans": total_scans,
            "open_networks": open_count,
            "open_ratio": round(open_ratio, 2),
            "anomalies_count": anomaly_count,
            "evil_twins": type_counts[AnomalyType.EVIL_TWIN] + type_counts[AnomalyType.ROGUE_AP],
            "arp_spoofs": type_counts[AnomalyType.ARP_SPOOF],
        },
    }


def get_all_locations_risk(db: Session, target_date: date) -> List[Dict[str, Any]]:
    """
    Computes risk summaries for all registered locations on a given date.
    """
    locations = db.query(Location).all()
    results = []
    for loc in locations:
        results.append(get_location_risk(db, loc.id, target_date))
    return results