import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.routers.cases import router as cases_router
from app.routers.reports import router as reports_router
from app.routers.upload import router as upload_router

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("email_forensics")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    logger.info("Initializing SQLite database tables...")
    init_db()
    logger.info("Database initialized successfully.")
    yield


app = FastAPI(
    title="Email Fraud Forensic Analysis Platform API",
    description="Forensic analysis pipeline backend (Stage 1.5 Job Queue)",
    version="0.3.0",
    lifespan=lifespan,
)

# Allow frontend requests
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(upload_router, prefix="/api")
app.include_router(cases_router, prefix="/api")
app.include_router(reports_router, prefix="/api/cases")


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for platform liveness verification."""
    return {"status": "ok"}
