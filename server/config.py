# ============================================================
# Konfigurasi server Password Manager
# ============================================================

import os

# ── Server ───────────────────────────────────────────────────
HOST  = os.getenv("PM_HOST", "127.0.0.1")
PORT  = int(os.getenv("PM_PORT", 5000))
DEBUG = os.getenv("PM_DEBUG", "false").lower() == "true"

# ── Database ─────────────────────────────────────────────────
# Path ke file SQLite; bisa di-override lewat environment variable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.getenv("PM_DB_PATH", os.path.join(BASE_DIR, "pm_server.db"))