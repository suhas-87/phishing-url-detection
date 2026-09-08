"""
PhishGuard - Flask REST API Backend
Provides machine learning inference for URL phishing detection,
deep destination website intelligence (WHOIS, SSL, DNS, Server, Metadata),
serves the frontend UI, and handles secure redirection validation.
"""

import os
import json
import joblib
import numpy as np
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory

from feature_extractor import (
    extract_features,
    extract_features_dict,
    get_suspicious_indicators,
    FEATURE_NAMES
)

from url_analyzer import analyze_url_deep

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
@app.route("/analyze", methods=["POST", "OPTIONS"])
def predict():
    """
    Main prediction & intelligence endpoint.
    Expects JSON: { "url": "https://example.com" }
    Preserves all existing ML output while returning full Safe Website Report details
    or Phishing Diagnostic breakdowns.
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
            confidence = 90.0

        confidence = round(confidence, 1)

        # 4. Determine Prediction Label & Risk Level
        if pred_class == 1:
            prediction_label = "Phishing"
            risk_level = "High" if confidence >= 75.0 else "Medium"
        else:
            prediction_label = "Legitimate"
            risk_level = "Low" if confidence >= 60.0 else "Medium"

        is_safe = (pred_class == 0)

        # 5. Extract educational indicators for UI
        indicators = get_suspicious_indicators(raw_url, feature_dict)

        # 6. Deep Destination Intelligence & Real Website Information
        deep_info = analyze_url_deep(raw_url, prediction_label, confidence, feature_dict)

        # Clean up internal feature dict keys before returning
        clean_features = {k: v for k, v in feature_dict.items() if not k.startswith("_")}

        # 7. Compile categorized warnings & recommendations for phishing/suspicious URLs
        warning_reasons = []
        if not is_safe:
            for ind in indicators:
                if ind.get("type") in ("danger", "warning"):
                    warning_reasons.append(f"{ind.get('title')}: {ind.get('description')}")
            if feature_dict.get("is_ip_address"):
                warning_reasons.append("Direct IP address hosting masks fraudulent attacker infrastructure.")
            if feature_dict.get("has_https") == 0:
                warning_reasons.append("Unencrypted transmission allows eavesdropping and credential tampering.")
            if feature_dict.get("suspicious_words_count", 0) > 0:
                warning_reasons.append(f"Security-sensitive keywords found: {', '.join(feature_dict.get('_matched_suspicious_words', []))}")

            recommendation = "Do not visit this website. Entering personal credentials or financial details here may result in identity theft or account compromise."
        else:
            recommendation = "The Machine Learning model classified this domain structure as safe and standard. Confirm destination identity before entering sensitive information."

        return jsonify({
            # Original preserved fields
            "url": raw_url,
            "prediction": prediction_label,
            "confidence": confidence,
            "risk_level": risk_level,
            "model_used": metadata.get("best_model", model.__class__.__name__),
            "indicators": indicators,
            "features": clean_features,

            # New enhanced fields
            "is_safe": is_safe,
            "can_redirect": is_safe,
            "security_score": deep_info.get("security_score", 95 if is_safe else 15),
            "trust_score": deep_info.get("trust_score", 95 if is_safe else 15),
            "timestamp": deep_info.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
            "warning_reasons": warning_reasons,
            "recommendation": recommendation,

            # Full categorized website information
            "domain_info": deep_info.get("domain_info", {}),
            "organization_info": deep_info.get("organization_info", {}),
            "ssl_info": deep_info.get("ssl_info", {}),
            "server_info": deep_info.get("server_info", {}),
            "website_metadata": deep_info.get("website_metadata", {})
        })

    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

@app.route("/api/verify-redirect", methods=["POST"])
def verify_redirect():
    """
    Validates that a requested outbound URL was classified as Safe by the ML model.
    Prevents open redirect vulnerabilities by blocking any malicious/unverified destinations.
    """
    global model
    if model is None:
        load_ml_assets()

    data = request.get_json(silent=True) or {}
    target_url = str(data.get("url", "")).strip()

    if not target_url:
        return jsonify({"status": "blocked", "error": "Missing destination URL."}), 400

    try:
        # Re-verify through feature extraction & model
        feat_dict = extract_features_dict(target_url)
        vector = np.array([feat_dict[name] for name in FEATURE_NAMES], dtype=float).reshape(1, -1)
        pred_class = int(model.predict(vector)[0])

        if pred_class == 1:
            return jsonify({
                "status": "blocked",
                "error": "Redirect blocked: destination is classified as phishing/malicious."
            }), 403

        return jsonify({
            "status": "authorized",
            "safe_url": target_url
        }), 200
    except Exception as e:
        return jsonify({"status": "blocked", "error": str(e)}), 500

if __name__ == "__main__":
    print("[*] Starting PhishGuard Server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
