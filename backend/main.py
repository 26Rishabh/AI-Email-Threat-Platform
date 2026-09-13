# ─────────────────────────────────────────────
#  main.py  —  FastAPI Application Entry Point
#
#  WHY THIS FILE:
#  This is the "front door" of the backend.
#  It creates the FastAPI app, registers all the
#  route groups, configures CORS (so the React
#  frontend on a different port can talk to it),
#  and starts the server.
#
#  HOW TO RUN:
#    cd backend
#    uvicorn main:app --reload --port 8000
#
#  After running, visit:
#    http://localhost:8000/docs   ← interactive API explorer
#    http://localhost:8000/health ← health check
# ─────────────────────────────────────────────
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from database.connection import ping_db
from modules.ai_detection import load_model
from routers.analysis import router as analysis_router
from routers.auth import router as auth_router
from routers.report import router as report_router

load_dotenv()

# ── Create the FastAPI application ────────────
app = FastAPI(
    title="AI Email Threat Detection Platform",
    description=(
        "An AI-assisted cybersecurity platform that analyzes suspicious emails, "
        "detects phishing and impersonation threats, performs email-header and "
        "infrastructure forensics, and generates structured forensic reports."
    ),
    version="1.0.0",
    docs_url="/docs",       # Interactive API docs (Swagger UI)
    redoc_url="/redoc",     # Alternative API docs (ReDoc)
)

# ── CORS Configuration ────────────────────────
# CORS (Cross-Origin Resource Sharing) allows the React frontend
# running on http://localhost:5173 (Vite dev server) to call the
# FastAPI backend on http://localhost:8000.
# Without this, the browser would block the requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "https://ai-email-threat-platform.vercel.app",
        "https://*.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register route groups ─────────────────────
# Each router handles a specific area of the API.
app.include_router(analysis_router)
app.include_router(auth_router)
app.include_router(report_router)


# ── Startup event ─────────────────────────────
@app.on_event("startup")
async def startup_event():
    """
    Runs once when the server starts.
    Checks that MongoDB is reachable, loads the ML model, prints status.
    """
    db_ok = ping_db()
    if db_ok:
        print("✓ MongoDB connection: OK")
    else:
        print("✗ WARNING: Cannot connect to MongoDB. Check your MONGO_URI in .env")

    model_ok = load_model()
    if model_ok:
        print("✓ ML phishing detection model: loaded")
    else:
        print("ℹ ML model not found — using rule-based detection. Run: python scripts/train_model.py")

    print("✓ Server started. API docs at http://localhost:8000/docs")


# ── Health check endpoint ─────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Simple health check endpoint.
    Returns the status of the server and database connection.
    Used by deployment platforms (Render) to verify the server is up.
    """
    db_ok = ping_db()
    return {
        "status":   "ok" if db_ok else "degraded",
        "database": "connected" if db_ok else "unreachable",
        "version":  "1.0.0",
    }


# ── Root endpoint ─────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "message": "AI Email Threat Detection Platform API",
        "docs":    "/docs",
        "version": "1.0.0",
    }
