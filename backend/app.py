"""
PhishGuard - Flask REST API Backend
Provides machine learning inference for URL phishing detection,
serves the frontend UI, and provides model metrics endpoints.
"""

import os
import json
import joblib
import numpy as np
from flask import Flask, request, jsonify, send_from_directory

from feature_extractor import (
    extract_features,
    extract_features_dict,
    get_suspicious_indicators,
    FEATURE_NAMES
)

# Initialize Flask application
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
SCREENSHOTS_DIR = os.path.join(PROJECT_ROOT, "screenshots")
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")

app = Flask(__name__, static_folder=FRONTEND_DIR)

# Load trained model and metadata
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

model = None
metadata = {}

def load_ml_assets():
    global model, metadata
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            print(f"[*] Trained model loaded successfully from: {MODEL_PATH}")
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            model = None
    else:
        print(f"[!] Model file not found at {MODEL_PATH}. Please run train_model.py first.")

    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            print(f"[*] Metadata loaded successfully.")
        except Exception as e:
            print(f"[!] Error loading metadata: {e}")
            metadata = {}

# Initial load
load_ml_assets()

# Enable CORS headers for cross-origin frontend requests
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# ==========================================
# STATIC FRONTEND ROUTES
# ==========================================

@app.route("/")
def serve_index():
    """Serves the main application page."""
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    """Serves generated plots and screenshots."""
    return send_from_directory(SCREENSHOTS_DIR, filename)

@app.route("/<path:path>")
def serve_static(path):
    """Serves CSS, JS, and asset files."""
    if os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return jsonify({"error": "File not found"}), 404

# ==========================================
# API ENDPOINTS
# ==========================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """Returns the API health status and whether the ML model is active."""
    return jsonify({
        "status": "online",
        "model_loaded": model is not None,
        "champion_algorithm": metadata.get("best_model", "Unknown")
    })

@app.route("/api/model-info", methods=["GET"])
def get_model_info():
    """Returns training metrics, algorithm comparisons, and feature lists."""
    if not metadata:
        return jsonify({
            "error": "Model metadata not available. Train the model first."
        }), 404
    return jsonify(metadata)

@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    """
    Main prediction endpoint.
    Expects JSON: { "url": "https://example.com" }
    Returns:
      - url
      - prediction: 'Legitimate' or 'Phishing'
      - confidence: percentage (e.g. 96.4)
      - risk_level: 'Low', 'Medium', 'High'
      - indicators: educational breakdown of flagged characteristics
      - features: exact numerical values fed to the ML model
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    global model
    if model is None:
        load_ml_assets()
        if model is None:
            return jsonify({
                "error": "Trained model not found on server. Please run train_model.py first."
            }), 500

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field is required."}), 400

    raw_url = str(data["url"]).strip()
    if not raw_url:
        return jsonify({"error": "URL cannot be empty."}), 400

    # Basic structure validation
    if len(raw_url) < 3 or ("." not in raw_url and "localhost" not in raw_url):
        return jsonify({"error": "Invalid URL format. Please enter a valid website address."}), 400

    try:
        # 1. Extract feature dictionary and numerical vector
        feature_dict = extract_features_dict(raw_url)
        feature_vector = np.array([feature_dict[name] for name in FEATURE_NAMES], dtype=float).reshape(1, -1)

        # 2. Model Prediction
        pred_class = int(model.predict(feature_vector)[0])  # 0 = Legitimate, 1 = Phishing

        # 3. Calculate Confidence Score
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(feature_vector)[0]
            confidence = float(probabilities[pred_class]) * 100.0
        else:
            # Fallback for models without predict_proba
            confidence = 90.0

        confidence = round(confidence, 1)

        # 4. Determine Prediction Label & Risk Level
        if pred_class == 1:
            prediction_label = "Phishing"
            risk_level = "High" if confidence >= 75.0 else "Medium"
        else:
            prediction_label = "Legitimate"
            risk_level = "Low" if confidence >= 60.0 else "Medium"

        # 5. Extract educational indicators for UI
        indicators = get_suspicious_indicators(raw_url, feature_dict)

        # Clean up internal feature dict keys before returning
        clean_features = {k: v for k, v in feature_dict.items() if not k.startswith("_")}

        return jsonify({
            "url": raw_url,
            "prediction": prediction_label,
            "confidence": confidence,
            "risk_level": risk_level,
            "model_used": metadata.get("best_model", model.__class__.__name__),
            "indicators": indicators,
            "features": clean_features
        })

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

if __name__ == "__main__":
    print("[*] Starting PhishGuard Server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
