import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DEBUG = os.getenv("DEBUG", "False") == "True"
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8000))
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///krypt.db")
    SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 300))