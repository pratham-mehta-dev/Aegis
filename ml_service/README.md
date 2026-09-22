# ML service

TF-IDF + LogisticRegression trained at startup on 18 hardcoded samples
(`TRAINING_DATA` in `app.py`). This is a **demo/toy model** — confidence values
are probability outputs, not measured accuracy. Do not quote accuracy metrics
for it; none exist.

## Provenance

Training samples are hand-written by the project authors (no external dataset,
no licence concerns). Class balance is intentionally small and uneven.

## Run

```
pip install -r requirements.txt
python app.py    # binds 127.0.0.1:5000
```

## Upgrading to a real model (Phase 7)

1. Pick a labelled dataset (e.g. a public SQLi/XSS corpus) — document source,
   licence, size, class balance here.
2. Move training into a separate script; train/validation/test split; report
   per-class precision/recall/F1 and a confusion matrix.
3. Save with `joblib`; load at startup instead of fitting on import; expose the
   version string via `/health`.
