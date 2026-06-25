"""
NetWatch — Network Flow Feature Engineering
============================================
Transforms raw network flow records into ML-ready features.

Raw flow fields:
  timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
  duration_sec, src_bytes, dst_bytes, packet_count,
  failed_conns, unique_ports

Engineered features (12 total):
  bytes_per_sec, packets_per_sec, src_dst_byte_ratio,
  avg_packet_size, failed_ratio, log_duration, log_total_bytes,
  is_high_port, hour_sin, hour_cos, protocol_encoded,
  connection_intensity
"""

import math
import pandas as pd
import numpy as np
from typing import List

# Protocol encoding map
PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

FEATURE_NAMES = [
    "bytes_per_sec",
    "packets_per_sec",
    "src_dst_byte_ratio",
    "avg_packet_size",
    "failed_ratio",
    "log_duration",
    "log_total_bytes",
    "is_high_port",
    "hour_sin",
    "hour_cos",
    "protocol_encoded",
    "connection_intensity",
]


def safe_ratio(a, b, default=0.0):
    """Safely compute a/b, returning default if b is zero."""
    return float(a) / float(b) if b != 0 else default


def extract_features_from_row(row: dict) -> dict:
    """
    Extract engineered ML features from a single network flow record.

    Args:
        row: Dict with raw flow fields (from CSV or live capture)

    Returns:
        Dict of feature_name -> float
    """
    duration      = max(float(row.get("duration_sec", 0.001)), 0.001)
    src_bytes     = float(row.get("src_bytes", 0))
    dst_bytes     = float(row.get("dst_bytes", 0))
    packets       = max(float(row.get("packet_count", 1)), 1)
    failed        = float(row.get("failed_conns", 0))
    unique_ports  = float(row.get("unique_ports", 1))
    dst_port      = int(row.get("dst_port", 0))
    protocol_raw  = str(row.get("protocol", "TCP")).upper()
    total_bytes   = src_bytes + dst_bytes

    # Parse hour from timestamp string
    try:
        ts_str = str(row.get("timestamp", "2024-01-01T12:00:00"))
        hour   = int(ts_str[11:13])
    except (ValueError, IndexError):
        hour   = 12

    # ── Feature calculations ────────────────────────────────────────────────

    # Throughput: bytes transferred per second
    # HIGH → possible exfiltration or DDoS
    bytes_per_sec    = total_bytes / duration

    # Packet rate: packets per second
    # VERY HIGH → DDoS flood; VERY LOW → C2 beacon
    packets_per_sec  = packets / duration

    # Asymmetry: ratio of outbound to total bytes
    # HIGH (near 1.0) → exfiltration (more data leaving than arriving)
    src_dst_byte_ratio = safe_ratio(src_bytes, total_bytes, default=0.5)

    # Average packet size in bytes
    # VERY SMALL → port scan probes; VERY LARGE → bulk transfer
    avg_packet_size  = total_bytes / packets

    # Failure rate: proportion of connections that failed
    # HIGH → port scan or brute force
    failed_ratio     = safe_ratio(failed, unique_ports + failed)

    # Log-scaled duration (compresses huge range from 0.001s to 3600s)
    log_duration     = math.log1p(duration)

    # Log-scaled total bytes (compresses range from 0 to gigabytes)
    log_total_bytes  = math.log1p(total_bytes)

    # High port flag: destination port > 1024 is non-standard service
    # Tunnelling and C2 often use high ports
    is_high_port     = float(dst_port > 1024 and dst_port not in [8080, 8443, 3389])

    # Cyclical encoding of hour (preserves 23:00 ~ 00:00 proximity)
    hour_sin         = math.sin(2 * math.pi * hour / 24)
    hour_cos         = math.cos(2 * math.pi * hour / 24)

    # Protocol as integer
    protocol_encoded = float(PROTO_MAP.get(protocol_raw, 3))

    # Connection intensity: combines port diversity and packet rate
    # PORT SCAN has high unique_ports; DDoS has high packets_per_sec
    connection_intensity = math.log1p(unique_ports) * math.log1p(packets_per_sec)

    return {
        "bytes_per_sec":          bytes_per_sec,
        "packets_per_sec":        packets_per_sec,
        "src_dst_byte_ratio":     src_dst_byte_ratio,
        "avg_packet_size":        avg_packet_size,
        "failed_ratio":           failed_ratio,
        "log_duration":           log_duration,
        "log_total_bytes":        log_total_bytes,
        "is_high_port":           is_high_port,
        "hour_sin":               hour_sin,
        "hour_cos":               hour_cos,
        "protocol_encoded":       protocol_encoded,
        "connection_intensity":   connection_intensity,
    }


def extract_features_dataframe(df: pd.DataFrame) -> np.ndarray:
    """
    Extract features from a full DataFrame of flow records.

    Returns:
        NumPy array of shape (n_flows, 12)
    """
    rows = df.to_dict(orient="records")
    feature_dicts = [extract_features_from_row(r) for r in rows]
    return pd.DataFrame(feature_dicts)[FEATURE_NAMES].values


# ── Quick demo ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample_flows = [
        {
            "timestamp": "2024-11-01T14:32:10",
            "src_ip": "192.168.1.15", "dst_ip": "8.8.8.8",
            "src_port": 52441, "dst_port": 443, "protocol": "TCP",
            "duration_sec": 12.5, "src_bytes": 1200, "dst_bytes": 85000,
            "packet_count": 120, "failed_conns": 0, "unique_ports": 1,
            "label": "normal",
        },
        {
            "timestamp": "2024-11-01T03:15:44",  # 3am
            "src_ip": "192.168.1.22", "dst_ip": "45.155.91.8",
            "src_port": 59001, "dst_port": 443, "protocol": "TCP",
            "duration_sec": 180.0, "src_bytes": 950_000_000, "dst_bytes": 2000,
            "packet_count": 640000, "failed_conns": 0, "unique_ports": 1,
            "label": "attack",
        },
        {
            "timestamp": "2024-11-01T09:01:02",
            "src_ip": "45.130.22.88", "dst_ip": "192.168.1.5",
            "src_port": 55000, "dst_port": 22, "protocol": "TCP",
            "duration_sec": 45.0, "src_bytes": 18000, "dst_bytes": 12000,
            "packet_count": 600, "failed_conns": 298, "unique_ports": 1,
            "label": "attack",
        },
    ]

    print("=" * 60)
    print("  NetWatch — Feature Extraction Demo")
    print("=" * 60)
    labels = ["✅ Normal web", "⚠️  Exfiltration (3am, huge upload)", "⚠️  Brute force SSH"]
    for flow, label in zip(sample_flows, labels):
        feats = extract_features_from_row(flow)
        print(f"\n  {label}")
        print(f"    bytes/sec         : {feats['bytes_per_sec']:>15,.0f}")
        print(f"    packets/sec       : {feats['packets_per_sec']:>15,.1f}")
        print(f"    outbound ratio    : {feats['src_dst_byte_ratio']:>15.3f}")
        print(f"    failed ratio      : {feats['failed_ratio']:>15.3f}")
        print(f"    connection intens : {feats['connection_intensity']:>15.3f}")
        print(f"    hour_cos (timing) : {feats['hour_cos']:>15.3f}")
