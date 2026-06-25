"""
NetWatch — Isolation Forest Training Pipeline
==============================================
Trains an unsupervised anomaly detector on normal network traffic.

Why Isolation Forest?
  - No labelled attack examples needed
  - Works by isolating outliers via random splits
  - Anomalies are isolated in fewer cuts (they are statistically rare)
  - Fast: O(n log n) training, O(log n) inference
  - Produces an anomaly score for ranking alerts by severity

The model ONLY trains on normal traffic — it learns the "shape" of
normal, then flags anything that deviates from it at inference time.

Usage:
    python src/train.py
    python src/train.py --data data/network_flows.csv --contamination 0.05
"""

import os
import sys
import pickle
import argparse
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.features import extract_features_dataframe, FEATURE_NAMES


def load_data(filepath):
    print(f"[*] Loading: {filepath}")
    df = pd.read_csv(filepath)
    print(f"    Total flows   : {len(df)}")
    print(f"    Normal flows  : {(df.label == 'normal').sum()}")
    print(f"    Attack flows  : {(df.label == 'attack').sum()}")
    return df


def build_model(contamination=0.05, n_estimators=200, random_state=42):
    """
    Build the anomaly detection pipeline:
      1. RobustScaler: scales features using median/IQR (resistant to outliers)
      2. IsolationForest: unsupervised anomaly detector

    contamination: expected fraction of anomalies (tunable hyperparameter)
    n_estimators:  number of isolation trees (more = more stable)
    """
    return Pipeline([
        ("scaler",  RobustScaler()),
        ("iforest", IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,
        ))
    ])


def evaluate(model, X, y_true_binary, label=""):
    """
    Evaluate model. IsolationForest returns:
       1  = normal (inlier)
      -1  = anomaly (outlier)
    We convert to match our binary label (1=attack, 0=normal).
    """
    raw_preds = model.predict(X)             # 1 or -1
    y_pred    = (raw_preds == -1).astype(int)  # 1=attack, 0=normal
    scores    = -model.score_samples(X)      # higher = more anomalous

    print(f"\n  {'─'*48}")
    print(f"  Evaluation: {label}")
    print(f"  {'─'*48}")
    print(classification_report(y_true_binary, y_pred,
                                target_names=["Normal", "Attack"],
                                digits=3))
    cm = confusion_matrix(y_true_binary, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion matrix:")
    print(f"    True Negatives  (normal caught)  : {tn}")
    print(f"    False Positives (false alarms)   : {fp}")
    print(f"    False Negatives (missed attacks) : {fn}")
    print(f"    True Positives  (attacks caught) : {tp}")
    print(f"\n  Detection rate  : {tp/(tp+fn)*100:.1f}%")
    print(f"  False alarm rate: {fp/(fp+tn)*100:.1f}%")

    return y_pred, scores


def feature_importance_proxy(model, X, feature_names):
    """
    Isolation Forest doesn't have built-in feature importance.
    We approximate by measuring how anomaly scores change when
    each feature is randomly permuted (permutation importance proxy).
    """
    base_scores = -model.score_samples(X)
    importances = {}
    rng = np.random.default_rng(42)

    for i, fname in enumerate(feature_names):
        X_perm = X.copy()
        rng.shuffle(X_perm[:, i])
        perm_scores = -model.score_samples(X_perm)
        importances[fname] = float(np.mean(np.abs(perm_scores - base_scores)))

    return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))


def main(data_path="data/network_flows.csv",
         output_dir="models/",
         contamination=0.05):

    print("\n" + "="*55)
    print("  NetWatch — Anomaly Detection Training Pipeline")
    print("="*55)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Load & split data ────────────────────────────────────────
    df = load_data(data_path)

    # IsolationForest trains ONLY on normal traffic
    df_normal  = df[df["label"] == "normal"].reset_index(drop=True)
    df_all     = df.reset_index(drop=True)

    X_train    = extract_features_dataframe(df_normal)
    X_all      = extract_features_dataframe(df_all)
    y_all      = (df_all["label"] == "attack").astype(int).values

    print(f"\n[*] Training on {len(X_train)} normal flows only")
    print(f"[*] Evaluating on all {len(X_all)} flows")
    print(f"[*] Contamination param: {contamination}")

    # ── Train ────────────────────────────────────────────────────
    print("\n[*] Training Isolation Forest...")
    model = build_model(contamination=contamination)

    # Pipeline's scaler step needs to be fit on training data only
    model.named_steps["scaler"].fit(X_train)
    X_train_scaled = model.named_steps["scaler"].transform(X_train)
    model.named_steps["iforest"].fit(X_train_scaled)
    print("[+] Training complete")

    # ── Evaluate ─────────────────────────────────────────────────
    X_all_scaled = model.named_steps["scaler"].transform(X_all)
    y_pred, scores = evaluate(model.named_steps["iforest"],
                              X_all_scaled, y_all, "Isolation Forest")

    # ── Feature importance (proxy) ───────────────────────────────
    print("\n[*] Computing feature importance (permutation proxy)...")
    importance = feature_importance_proxy(
        model.named_steps["iforest"], X_all_scaled, FEATURE_NAMES
    )
    print("\n  Top features by anomaly contribution:")
    for rank, (fname, score) in enumerate(list(importance.items())[:8], 1):
        bar = "█" * int(score * 500)
        print(f"    {rank}. {fname:<25} {bar} {score:.4f}")

    # ── Save model ───────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "netwatch_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump({"pipeline": model, "feature_names": FEATURE_NAMES,
                     "importance": importance, "trained_at": datetime.now().isoformat()}, f)
    print(f"\n[+] Model saved → {model_path}")
    print(f"\n  Next step: python src/detect.py --input data/network_flows.csv")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch — Train anomaly detector")
    parser.add_argument("--data",          default="data/network_flows.csv")
    parser.add_argument("--output",        default="models/")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected fraction of anomalies (0.01–0.15)")
    args = parser.parse_args()
    main(data_path=args.data, output_dir=args.output, contamination=args.contamination)
