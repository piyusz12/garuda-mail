import os
from pathlib import Path
from enum import Enum

BASE_DIR = Path(__file__).resolve().parent.parent

class OverlapPolicy(str, Enum):
    FIRST_WINS = "FIRST_WINS"
    LAST_WINS = "LAST_WINS"

class Config:
    # Directories
    OUTPUT_DIR = BASE_DIR / "output"
    SESSIONS_DIR = OUTPUT_DIR / "sessions"
    STREAMS_DIR = OUTPUT_DIR / "streams"
    
    # TCP Reassembly Settings
    OVERLAP_POLICY = OverlapPolicy.FIRST_WINS
    MAX_SESSION_DURATION_SEC = 3600  # 1 hour
    IDLE_TIMEOUT_SEC = 300  # 5 minutes
    
    # Setup
    @classmethod
    def setup_directories(cls):
        cls.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        cls.STREAMS_DIR.mkdir(parents=True, exist_ok=True)

config = Config()
