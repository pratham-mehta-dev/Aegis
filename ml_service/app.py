"""Aegis application-layer ML service.

Demo-grade classifier: TF-IDF (char+word n-grams) + LogisticRegression trained at
startup on a small hardcoded sample set. This is a TOY MODEL — confidence values
are not calibrated accuracy. See README.md for provenance and upgrade path.
"""
from flask import Flask, jsonify, request
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

app = Flask(__name__)

CLASSES = ["Benign", "SQL Injection", "XSS", "Port Scan", "DoS Flood", "Brute Force"]

SEVERITY = {
    "SQL Injection": "Critical",
    "DoS Flood": "Critical",
    "Port Scan": "High",
    "Brute Force": "High",
    "XSS": "Medium",
    "Benign": "Low",
}

MODEL_NAME = "tfidf-logreg-demo"
MODEL_VERSION = "0.1.0"

TRAINING_DATA = [
    # Benign
    ("order status for my recent purchase please", "Benign"),
    ("hello world this is a normal review", "Benign"),
    ("searching for wireless headphones under 50 dollars", "Benign"),
    ("great product, fast shipping, would buy again", "Benign"),
    ("how do I reset my account password", "Benign"),
    # SQL Injection
    ("' OR '1'='1' --", "SQL Injection"),
    ("admin'--", "SQL Injection"),
    ("union select username password from users", "SQL Injection"),
    ("' OR 1=1 DROP TABLE users; --", "SQL Injection"),
    ("1' AND SLEEP(5)--", "SQL Injection"),
    # XSS
    ("<script>alert(1)</script>", "XSS"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("javascript:alert(document.cookie)", "XSS"),
    ("<svg onload=alert('xss')>", "XSS"),
    # Network layer phrases (kept so the demo taxonomy is complete)
    ("nmap -sS -p- 192.168.1.1 port scan", "Port Scan"),
    ("hping3 --flood -S target dos attack", "DoS Flood"),
    ("hydra -l admin -P passwords.txt ssh brute force", "Brute Force"),
]

model = Pipeline(
    [
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, random_state=42)),
    ]
)
model.fit([t for t, _ in TRAINING_DATA], [l for _, l in TRAINING_DATA])


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "model": MODEL_NAME,
            "version": MODEL_VERSION,
            "classes": CLASSES,
            "training_samples": len(TRAINING_DATA),
            "note": "demo model; confidence is not measured accuracy",
        }
    )


@app.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}
    payload = str(data.get("payload", ""))
    if not payload.strip():
        return jsonify({"error": "payload is required"}), 400
    if len(payload) > 8192:
        return jsonify({"error": "payload too large"}), 400

    probs = model.predict_proba([payload])[0]
    classes = list(model.classes_)
    best = int(probs.argmax())
    label = classes[best]
    return jsonify(
        {
            "malicious": label != "Benign",
            "type": label,
            "confidence": round(float(probs[best]), 4),
            "severity": SEVERITY[label],
            "layer": "Application",
            "model": f"{MODEL_NAME}@{MODEL_VERSION}",
        }
    )


if __name__ == "__main__":
    # Loopback only: the Node API proxies to this service.
    app.run(host="127.0.0.1", port=5000)
