# AI-Powered Email Threat Detection & Forensic Intelligence Platform

## Quick Start

### Prerequisites
- Python 3.10+, Node.js 18+, MongoDB Atlas account

### Backend Setup
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate          # Windows
pip install -r requirements.txt
pip install pytest
# Create .env file (copy .env.example, fill MONGO_URI)
python scripts/seed_admin.py
python scripts/train_model.py
uvicorn main:app --reload --port 8000
# API docs → http://localhost:8000/docs
```

### Frontend Setup
```bash
cd frontend
npm install
# Create .env.local with: VITE_API_URL=http://localhost:8000
npm run dev
# App → http://localhost:5173
```

### Default Login
- Username: `admin` | Password: `admin123`

---

## Project Structure
```
Project/
├── backend/
│   ├── main.py                     # FastAPI entry point
│   ├── requirements.txt
│   ├── modules/
│   │   ├── email_parser.py         # Module 1  — Email parsing
│   │   ├── header_forensics.py     # Module 2  — Header analysis
│   │   ├── auth_analysis.py        # Module 3  — SPF/DKIM/DMARC
│   │   ├── ai_detection.py         # Module 4  — ML phishing detection
│   │   ├── url_analysis.py         # Module 5  — URL analysis
│   │   ├── domain_intel.py         # Module 6  — DNS intelligence
│   │   ├── ip_intel.py             # Module 7  — IP geolocation
│   │   ├── correlation.py          # Module 8  — Threat correlation
│   │   ├── risk_scoring.py         # Module 9  — Risk score (0-100)
│   │   ├── report_generator.py     # Module 13 — PDF forensic report
│   │   └── evidence.py             # Module 12 — SHA-256 evidence
│   ├── routers/
│   │   ├── analysis.py             # POST /api/analyze
│   │   ├── auth.py                 # POST /api/auth/login
│   │   └── report.py               # GET  /api/report/{case_id}
│   ├── scripts/
│   │   ├── seed_admin.py           # Create default admin user
│   │   └── train_model.py          # Train ML model
│   ├── ml_models/                  # Saved trained model (.pkl)
│   ├── test_emails/                # Sample .eml test files
│   └── tests/                      # 56 unit tests
└── frontend/
    ├── src/
    │   ├── pages/                  # Login, Upload, Dashboard, Cases
    │   ├── components/             # RiskBadge, IPMap, Graph, etc.
    │   ├── api/client.js           # Axios API layer
    │   └── context/AuthContext.jsx # JWT auth state
    └── .env.local                  # VITE_API_URL=http://localhost:8000
```

## Deployment

### Backend → Render
1. Push to GitHub
2. New Web Service on render.com → connect repo → Root: `backend`
3. Build: `pip install -r requirements.txt`
4. Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add env vars: `MONGO_URI`, `JWT_SECRET`, `IP_API_URL`

### Frontend → Vercel
1. New Project on vercel.com → connect repo → Root: `frontend`
2. Add env var: `VITE_API_URL=https://your-render-url.onrender.com`
3. Deploy

## Tech Stack
| Layer | Technology |
|---|---|
| Frontend | React + Vite + Tailwind CSS |
| Backend | Python + FastAPI |
| ML | scikit-learn (Random Forest + TF-IDF) |
| Database | MongoDB Atlas |
| PDF | ReportLab |
| Maps | Leaflet + OpenStreetMap |
| Auth | JWT |
| Deploy | Vercel (frontend) + Render (backend) |
