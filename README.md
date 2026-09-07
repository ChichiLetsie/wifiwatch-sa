# WiFiWatch SA

A public Wi-Fi risk-awareness dashboard and detection platform designed for South African transport interchanges, malls, and public hotspots.

WiFiWatch SA helps users visualize and understand wireless threats such as **Rogue APs**, **Evil Twins**, and **ARP Poisoning** through transparent heuristics and educational dashboards.

Read our public transparency commitment in [docs/ETHICS.md](docs/ETHICS.md).

---

## Getting Started

### Prerequisites
- Python 3.10+
- SQLite3

### 1. Setup Virtual Environment & Dependencies
```bash
cd backend
python3 -m venv venv
source .venv/bin/activate
pip install -r requirements.txt

python3 init_db.py
uvicorn app.main:app --reload --port 8000

python3 -m backend.synthetic_generator --days 7 --events-per-day 200
python3 -m synthetic_generator --days 7 --events-per-day 200