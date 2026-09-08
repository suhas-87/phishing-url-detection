"""
PhishGuard - Root Application Entrypoint for Cloud Deployments (Render / Gunicorn)
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from backend.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting PhishGuard on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
