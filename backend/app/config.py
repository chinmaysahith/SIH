import os
from pathlib import Path

# Project root resolution
# backend/app/config.py -> parent(app) -> parent(backend) -> parent(project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Quarantine storage directory
QUARANTINE_DIR_ENV = os.getenv("QUARANTINE_DIR")
if QUARANTINE_DIR_ENV:
    QUARANTINE_DIR = Path(QUARANTINE_DIR_ENV).resolve()
else:
    QUARANTINE_DIR = (PROJECT_ROOT / "data" / "quarantine").resolve()

# Attachments storage directory (Stage 2)
ATTACHMENTS_DIR_ENV = os.getenv("ATTACHMENTS_DIR")
if ATTACHMENTS_DIR_ENV:
    ATTACHMENTS_DIR = Path(ATTACHMENTS_DIR_ENV).resolve()
else:
    ATTACHMENTS_DIR = (PROJECT_ROOT / "data" / "attachments").resolve()

# Ensure directories exist
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)

# Database URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{PROJECT_ROOT / 'data' / 'forensic_cases.db'}",
)

# File upload limits
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Allowed file extensions
ALLOWED_EXTENSIONS = {".eml", ".msg"}

# Redis and RQ Job Queue configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
QUEUE_NAME = os.getenv("QUEUE_NAME", "email_analysis")

# Parser versioning (Stage 2)
PARSER_VERSION = "1.0.0"

# IOC Intelligence Engine configuration (Stage 5)
IOC_DATA_DIR_ENV = os.getenv("IOC_DATA_DIR")
if IOC_DATA_DIR_ENV:
    IOC_DATA_DIR = Path(IOC_DATA_DIR_ENV).resolve()
else:
    IOC_DATA_DIR = (PROJECT_ROOT / "data" / "ioc").resolve()

IOC_DATA_DIR.mkdir(parents=True, exist_ok=True)
IOC_FEED_PATH = IOC_DATA_DIR / "indicators.json"
IOC_ENGINE_VERSION = "1.0.0"

# Geo / Origin Forensics configuration (Stage 6)
GEO_DATA_DIR_ENV = os.getenv("GEO_DATA_DIR")
if GEO_DATA_DIR_ENV:
    GEO_DATA_DIR = Path(GEO_DATA_DIR_ENV).resolve()
else:
    GEO_DATA_DIR = (PROJECT_ROOT / "data" / "geo").resolve()

GEO_DATA_DIR.mkdir(parents=True, exist_ok=True)
GEOIP_DATABASE_PATH = GEO_DATA_DIR / "geoip_database.json"
NETWORK_INTEL_PATH = GEO_DATA_DIR / "network_intelligence.json"
GEO_ANALYSIS_VERSION = "1.0.0"

# Correlation Engine configuration (Stage 7)
CORRELATION_ENGINE_VERSION = "1.0.0"
CORRELATION_POLICY_VERSION = "1.0.0"
