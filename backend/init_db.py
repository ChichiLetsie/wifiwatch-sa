import sys
from pathlib import Path

# Allow imports from local backend folder
sys.path.append(str(Path(__file__).resolve().parent))

from app.database import Base, engine
from app.models import Location, ScanEvent, Anomaly


def init_database():
    print("Initialising SQLite database schemas for WiFiWatch SA...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully: locations, scan_events, anomalies.")


if __name__ == "__main__":
    init_database()