from datetime import date
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from sqlalchemy.orm import Session

from backend.app.database import get_db, Base, engine
from backend.app.models import Location, ScanEvent, Anomaly
from backend.app.schemas import (
    LocationResponse,
    LocationRiskResponse,
    ScanEventResponse,
    AnomalyResponse,
)
from backend.risk_scoring import get_location_risk, get_all_locations_risk

app = FastAPI(
    title="WiFiWatch SA API",
    description="Public Wi-Fi Risk Awareness & Anomaly Detection Dashboard",
    version="0.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route static frontend directory
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "ok"}


@app.get("/api/locations", response_model=List[LocationResponse], tags=["Locations"])
def list_locations(db: Session = Depends(get_db)):
    """List all monitored stations, malls, and township hotspots."""
    return db.query(Location.id, Location.name, Location.type, Location.lat, Location.lng).all()


@app.get("/api/locations/{location_id}/risk", response_model=LocationRiskResponse, tags=["Risk Scoring"])
def get_location_risk_endpoint(
    location_id: int,
    date: Optional[str] = Query(None, description="Date in YYYY-MM-DD format. Defaults to today."),
    db: Session = Depends(get_db),
):
    """Get the risk score, label, explanation, and metrics for a specific location."""
    target_date = date.fromisoformat(date) if date else date.today()
    result = get_location_risk(db, location_id, target_date)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@app.get("/api/risk/overview", response_model=List[LocationRiskResponse], tags=["Risk Scoring"])
def get_risk_overview(
    date: Optional[str] = Query(None, description="Date in YYYY-MM-DD format. Defaults to today."),
    db: Session = Depends(get_db),
):
    """Get risk scores for all monitored locations on a given date."""
    target_date = date.fromisoformat(date) if date else date.today()
    return get_all_locations_risk(db, target_date)


@app.get("/api/locations/{location_id}/events", response_model=List[ScanEventResponse], tags=["Telemetry"])
def list_location_events(
    location_id: int,
    limit: int = Query(50, le=200, description="Max number of events to return"),
    db: Session = Depends(get_db),
):
    """Retrieve recent scan events (metadata only) for a location."""
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(status_code=404, detail="Location not found")

    events = (
        db.query(ScanEvent)
        .filter(ScanEvent.location_id == location_id)
        .order_by(ScanEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return events


@app.get("/api/locations/{location_id}/anomalies", response_model=List[AnomalyResponse], tags=["Telemetry"])
def list_location_anomalies(
    location_id: int,
    limit: int = Query(50, le=200, description="Max number of anomalies to return"),
    db: Session = Depends(get_db),
):
    """Retrieve recent anomalies detected at a location."""
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(status_code=404, detail="Location not found")

    # Join Anomaly with ScanEvent to filter by location_id
    anomalies = (
        db.query(Anomaly)
        .join(ScanEvent, Anomaly.scan_event_id == ScanEvent.id)
        .filter(ScanEvent.location_id == location_id)
        .order_by(ScanEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return anomalies