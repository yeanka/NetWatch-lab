"""
NetWatch — Anomaly Detection & Alerting Engine
================================================
Loads the trained Isolation Forest model and scans network flows
for anomalies. Produces severity-ranked alerts with explanations.

Anomaly Score interpretation:
  > 0.70  → CRITICAL
  > 0.55  → HIGH
  > 0.40  → MEDIUM
  < 0.40  → LOW / normal

Usage:
    python src/detect.py --input data/network_flows.csv
    python src/detect.py --input data/network_flows.csv --top 20
    python src/detect.py --input data/network_flows.csv --threshold 0.55
"""

import os
import sys
import json
import pickle
import argparse
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.features import extract_features_dataframe, extract_features_from_row, FEATURE_NAMES

MODEL_PATH = "models/netwatch_model.pkl"


class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    YELLOW = "\033[33m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        print(f"[!] Model not found at {path}. Run: python src/train.py")
        sys.exit(1)
    with open(path, "rb") as f:
        return pickle.load(f)


def severity(score):
    if score > 0.70:
        return "CRITICAL", C.RED
    elif score > 0.55:
        return "HIGH",     C.ORANGE
    elif score > 0.40:
        return "MEDIUM",   C.YELLOW
    else:
        return "LOW",      C.GREEN


def infer_attack_type(feats: dict, score: float) -> str:
    """
    Heuristically infer the most likely attack type from feature values.
    Used to provide a human-readable alert category.
    """
    if feats["failed_ratio"] > 0.4 and feats["unique_ports"] > 50 if "unique_ports" in feats else False:
        return "Port Scan"
    if feats["packets_per_sec"] > 10000:
        return "DDoS Flood"
    if feats["src_dst_byte_ratio"] > 0.85 and feats["bytes_per_sec"] > 1_000_000:
        return "Data Exfiltration"
    if feats["failed_ratio"] > 0.5:
        return "Brute Force"
    if feats["packets_per_sec"] < 5 and feats["log_total_bytes"] < 8:
        return "C2 Beacon"
    if score > 0.60:
        return "Unknown Anomaly"
    return "Suspicious"


def explain_alert(row: dict, feats: dict, score: float) -> list:
    """Generate plain-English explanation bullets for an alert."""
    reasons = []

    if feats["packets_per_sec"] > 5000:
        reasons.append(f"Packet rate {feats['packets_per_sec']:,.0f} pkt/s — far above normal baseline")
    if feats["bytes_per_sec"] > 1_000_000:
        reasons.append(f"Throughput {feats['bytes_per_sec']/1e6:.1f} MB/s — abnormally high")
    if feats["src_dst_byte_ratio"] > 0.80:
        reasons.append(f"Outbound ratio {feats['src_dst_byte_ratio']:.0%} — data leaving more than arriving")
    if feats["failed_ratio"] > 0.3:
        reasons.append(f"Failure rate {feats['failed_ratio']:.0%} — many rejected connections")
    if feats["connection_intensity"] > 15:
        reasons.append(f"Connection intensity {feats['connection_intensity']:.1f} — unusually dense activity")
    hour_cos = feats["hour_cos"]
    hour_sin = feats["hour_sin"]
    import math
    hour = int(math.atan2(hour_sin, hour_cos) / (2 * math.pi) * 24) % 24
    if 1 <= hour <= 5:
        reasons.append(f"Activity at {hour:02d}:xx — outside business hours")
    if feats["log_duration"] < 0.5 and feats["packets_per_sec"] > 100:
        reasons.append("Very short-lived connection with high packet rate — probe pattern")
    if feats["avg_packet_size"] < 80:
        reasons.append(f"Avg packet {feats['avg_packet_size']:.0f} bytes — unusually small (possible scan)")

    if not reasons:
        reasons.append(f"Anomaly score {score:.3f} deviates from learned normal baseline")

    return reasons


def detect(model_data, input_path, threshold=0.40, top_n=None):
    pipeline     = model_data["pipeline"]
    scaler       = pipeline.named_steps["scaler"]
    iforest      = pipeline.named_steps["iforest"]

    print(f"\n{'='*58}")
    print(f"  NetWatch — Anomaly Detection Engine")
    print(f"{'='*58}")
    print(f"  Input  : {input_path}")
    print(f"  Model  : {model_data.get('trained_at','unknown')}")
    print(f"  Threshold: score > {threshold}")

    df      = pd.read_csv(input_path)
    X       = extract_features_dataframe(df)
    X_sc    = scaler.transform(X)

    raw_scores   = -iforest.score_samples(X_sc)   # higher = more anomalous
    predictions  = iforest.predict(X_sc)          # -1 = anomaly, 1 = normal

    # Normalize scores to 0-1 range
    s_min, s_max = raw_scores.min(), raw_scores.max()
    norm_scores  = (raw_scores - s_min) / (s_max - s_min + 1e-9)

    # Build alert list
    alerts = []
    for i, (idx, row) in enumerate(df.iterrows()):
        score = float(norm_scores[i])
        if score > threshold:
            row_dict = row.to_dict()
            feats    = extract_features_from_row(row_dict)
            atype    = infer_attack_type(feats, score)
            sev, _   = severity(score)
            alerts.append({
                "rank":        0,
                "score":       round(score, 4),
                "severity":    sev,
                "attack_type": atype,
                "timestamp":   str(row_dict.get("timestamp", "")),
                "src_ip":      str(row_dict.get("src_ip", "")),
                "dst_ip":      str(row_dict.get("dst_ip", "")),
                "dst_port":    int(row_dict.get("dst_port", 0)),
                "protocol":    str(row_dict.get("protocol", "")),
                "true_label":  str(row_dict.get("label", "unknown")),
                "reasons":     explain_alert(row_dict, feats, score),
            })

    alerts.sort(key=lambda x: x["score"], reverse=True)
    for i, a in enumerate(alerts):
        a["rank"] = i + 1

    if top_n:
        display_alerts = alerts[:top_n]
    else:
        display_alerts = alerts

    # ── Print alerts ──────────────────────────────────────────────────────────
    print(f"\n  Flows scanned  : {len(df)}")
    print(f"  Alerts raised  : {len(alerts)}")
    print(f"  Critical       : {sum(1 for a in alerts if a['severity'] == 'CRITICAL')}")
    print(f"  High           : {sum(1 for a in alerts if a['severity'] == 'HIGH')}")
    print(f"  Medium         : {sum(1 for a in alerts if a['severity'] == 'MEDIUM')}")

    if display_alerts:
        print(f"\n  {'─'*56}")
        print(f"  Top {len(display_alerts)} Alerts (ranked by anomaly score)")
        print(f"  {'─'*56}")

    for alert in display_alerts:
        sev_label, color = severity(alert["score"])
        true_ok   = "✓" if alert["true_label"] == "attack" else "✗"
        print(f"\n  #{alert['rank']:02d} [{color}{sev_label:<8}{C.RESET}] Score: {alert['score']:.4f}  {true_ok}")
        print(f"       Type     : {alert['attack_type']}")
        print(f"       Time     : {alert['timestamp']}")
        print(f"       {alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']} ({alert['protocol']})")
        for reason in alert["reasons"]:
            print(f"       • {reason}")

    # ── Save JSON ────────────────────────────────────────────────────────────
    out_path = "reports/alerts.json"
    os.makedirs("reports", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"scan_time": datetime.now().isoformat(),
                   "total_flows": len(df),
                   "alerts": alerts}, f, indent=2)
    print(f"\n[+] Full alert list saved → {out_path}")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="NetWatch — Detect network anomalies")
    parser.add_argument("--input",     default="data/network_flows.csv")
    parser.add_argument("--model",     default=MODEL_PATH)
    parser.add_argument("--threshold", type=float, default=0.40, help="Anomaly score threshold (0-1)")
    parser.add_argument("--top",       type=int,   default=15,   help="Show top N alerts")
    args = parser.parse_args()

    model_data = load_model(args.model)
    detect(model_data, args.input, threshold=args.threshold, top_n=args.top)


if __name__ == "__main__":
    main()
