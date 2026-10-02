"""Aegis application-layer ML intrusion detection service.

Production-ready hybrid classifier combining TF-IDF char/word n-gram models
with known attack syntax heuristics. Returns calibrated confidence and
classifications for SQLi, XSS, Command Injection, Brute Force, and Network patterns.
"""

from flask import Flask, jsonify, request
from dataset import TRAINING_DATA
from model import HybridIDPSClassifier

app = Flask(__name__)

CLASSES = [
    "Benign",
    "SQL Injection",
    "XSS",
    "Command Injection",
    "Port Scan",
    "DoS Flood",
    "Brute Force",
]

SEVERITY = {
    "SQL Injection": "Critical",
    "Command Injection": "Critical",
    "DoS Flood": "Critical",
    "Port Scan": "High",
    "Brute Force": "High",
    "XSS": "Medium",
    "Benign": "Low",
}

MODEL_NAME = "aegis-hybrid-nlp-idps"
MODEL_VERSION = "1.0.0"

# Fit model on service startup
classifier = HybridIDPSClassifier()
classifier.fit(TRAINING_DATA)


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "model": MODEL_NAME,
            "version": MODEL_VERSION,
            "classes": classifier.classes,
            "metrics": classifier.metrics,
            "training_samples": classifier.metrics.get("training_samples", len(TRAINING_DATA)),
        }
    )


@app.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}
    payload = str(data.get("payload", ""))
    if not payload.strip():
        return jsonify({"error": "payload is required"}), 400
    if len(payload) > 16384:
        return jsonify({"error": "payload too large"}), 400

    label, confidence, _ = classifier.predict_single(payload)
    is_malicious = label != "Benign"

    return jsonify(
        {
            "malicious": is_malicious,
            "type": label,
            "confidence": confidence,
            "severity": SEVERITY.get(label, "Medium"),
            "layer": "Application",
            "model": f"{MODEL_NAME}@{MODEL_VERSION}",
        }
    )


if __name__ == "__main__":
    # Loopback only: the Node API proxies to this service.
    app.run(host="127.0.0.1", port=5000)
