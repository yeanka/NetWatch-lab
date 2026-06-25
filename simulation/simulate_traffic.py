"""
NetWatch — Synthetic Network Traffic Simulator
================================================
Generates realistic network flow records containing:
  - Normal baseline traffic (web browsing, DNS, email, file transfers)
  - Injected attack traffic (port scans, DDoS, exfiltration, brute force, C2)

Each flow record represents a network connection summary (like NetFlow/IPFIX).

Output: data/network_flows.csv

Usage:
    python data/simulate_traffic.py
    python data/simulate_traffic.py --flows 10000 --attack-ratio 0.07
"""

import csv
import random
import math
import argparse
from datetime import datetime, timedelta

random.seed(42)

# ── IP address pools ──────────────────────────────────────────────────────────

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS = [f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(100)]
ATTACKER_IPS = [f"45.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(10)]

# Common service ports
WEB_PORTS   = [80, 443, 8080, 8443]
DNS_PORTS   = [53]
EMAIL_PORTS = [25, 465, 587, 993, 995]
FILE_PORTS  = [21, 22, 445, 3389]
ALL_PORTS   = list(range(1, 65536))

PROTOCOLS   = ["TCP", "UDP", "ICMP"]
PROTO_WEIGHTS = [0.75, 0.22, 0.03]

START_TIME  = datetime(2024, 11, 1, 6, 0, 0)

# ── Normal traffic generators ─────────────────────────────────────────────────

def normal_web(ts):
    duration = random.uniform(0.5, 30.0)
    src_bytes = random.randint(200, 2000)
    dst_bytes = random.randint(5000, 500000)
    return {
        "timestamp":        ts.isoformat(),
        "src_ip":           random.choice(INTERNAL_IPS),
        "dst_ip":           random.choice(EXTERNAL_IPS),
        "src_port":         random.randint(1024, 65535),
        "dst_port":         random.choice(WEB_PORTS),
        "protocol":         "TCP",
        "duration_sec":     round(duration, 3),
        "src_bytes":        src_bytes,
        "dst_bytes":        dst_bytes,
        "packet_count":     random.randint(10, 500),
        "failed_conns":     0,
        "unique_ports":     1,
        "label":            "normal",
        "attack_type":      "none",
    }

def normal_dns(ts):
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(INTERNAL_IPS),
        "dst_ip":       "8.8.8.8",
        "src_port":     random.randint(1024, 65535),
        "dst_port":     53,
        "protocol":     "UDP",
        "duration_sec": round(random.uniform(0.01, 0.5), 3),
        "src_bytes":    random.randint(30, 100),
        "dst_bytes":    random.randint(50, 400),
        "packet_count": random.randint(1, 4),
        "failed_conns": 0,
        "unique_ports": 1,
        "label":        "normal",
        "attack_type":  "none",
    }

def normal_file_transfer(ts):
    size = random.randint(100_000, 50_000_000)
    duration = size / random.uniform(500_000, 5_000_000)
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(INTERNAL_IPS),
        "dst_ip":       random.choice(INTERNAL_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice(FILE_PORTS),
        "protocol":     "TCP",
        "duration_sec": round(duration, 3),
        "src_bytes":    random.randint(1000, 50000),
        "dst_bytes":    size,
        "packet_count": random.randint(100, 5000),
        "failed_conns": 0,
        "unique_ports": 1,
        "label":        "normal",
        "attack_type":  "none",
    }

# ── Attack traffic generators ─────────────────────────────────────────────────

def attack_port_scan(ts):
    """Port scan: short-lived connections to many ports, mostly failures."""
    n_ports = random.randint(100, 1000)
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(ATTACKER_IPS),
        "dst_ip":       random.choice(INTERNAL_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice(ALL_PORTS),
        "protocol":     "TCP",
        "duration_sec": round(random.uniform(0.001, 0.1), 4),
        "src_bytes":    random.randint(40, 80),
        "dst_bytes":    random.randint(0, 60),
        "packet_count": random.randint(1, 3),
        "failed_conns": random.randint(n_ports // 2, n_ports),
        "unique_ports": n_ports,
        "label":        "attack",
        "attack_type":  "port_scan",
    }

def attack_ddos(ts):
    """DDoS: extreme packet volume in very short time."""
    duration = random.uniform(0.01, 2.0)
    packets  = random.randint(50000, 500000)
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(ATTACKER_IPS),
        "dst_ip":       random.choice(INTERNAL_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice(WEB_PORTS),
        "protocol":     random.choice(["TCP", "UDP"]),
        "duration_sec": round(duration, 3),
        "src_bytes":    packets * random.randint(60, 1500),
        "dst_bytes":    random.randint(0, 1000),
        "packet_count": packets,
        "failed_conns": 0,
        "unique_ports": 1,
        "label":        "attack",
        "attack_type":  "ddos",
    }

def attack_exfiltration(ts):
    """Data exfiltration: large outbound transfer, unusual hour."""
    exfil_hour = random.choice([1, 2, 3, 4, 23])
    exfil_ts   = ts.replace(hour=exfil_hour, minute=random.randint(0, 59))
    size       = random.randint(50_000_000, 2_000_000_000)
    duration   = size / random.uniform(1_000_000, 10_000_000)
    return {
        "timestamp":    exfil_ts.isoformat(),
        "src_ip":       random.choice(INTERNAL_IPS),
        "dst_ip":       random.choice(ATTACKER_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice([443, 8443, 4444, 6666]),
        "protocol":     "TCP",
        "duration_sec": round(duration, 1),
        "src_bytes":    size,
        "dst_bytes":    random.randint(500, 5000),
        "packet_count": random.randint(10000, 200000),
        "failed_conns": 0,
        "unique_ports": 1,
        "label":        "attack",
        "attack_type":  "exfiltration",
    }

def attack_brute_force(ts):
    """Brute force: many rapid failed logins to a single host."""
    attempts = random.randint(50, 500)
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(ATTACKER_IPS),
        "dst_ip":       random.choice(INTERNAL_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice([22, 3389, 21, 23]),
        "protocol":     "TCP",
        "duration_sec": round(attempts * random.uniform(0.1, 2.0), 2),
        "src_bytes":    attempts * random.randint(100, 500),
        "dst_bytes":    attempts * random.randint(100, 300),
        "packet_count": attempts * random.randint(3, 8),
        "failed_conns": attempts - random.randint(0, 3),
        "unique_ports": 1,
        "label":        "attack",
        "attack_type":  "brute_force",
    }

def attack_c2_beacon(ts):
    """C2 beacon: small, extremely regular low-volume connections."""
    return {
        "timestamp":    ts.isoformat(),
        "src_ip":       random.choice(INTERNAL_IPS),   # compromised host calls out
        "dst_ip":       random.choice(ATTACKER_IPS),
        "src_port":     random.randint(1024, 65535),
        "dst_port":     random.choice([443, 80, 8080]),
        "protocol":     "TCP",
        "duration_sec": round(random.uniform(0.1, 1.0), 3),
        "src_bytes":    random.randint(64, 256),        # tiny, consistent payload
        "dst_bytes":    random.randint(64, 256),
        "packet_count": random.randint(2, 6),
        "failed_conns": 0,
        "unique_ports": 1,
        "label":        "attack",
        "attack_type":  "c2_beacon",
    }

# ── Dataset builder ───────────────────────────────────────────────────────────

NORMAL_GENERATORS  = [normal_web, normal_web, normal_web, normal_dns, normal_dns, normal_file_transfer]
ATTACK_GENERATORS  = [attack_port_scan, attack_ddos, attack_exfiltration, attack_brute_force, attack_c2_beacon]

def simulate(n_flows=5000, attack_ratio=0.05, output="data/network_flows.csv"):
    import os
    os.makedirs("data", exist_ok=True)

    n_attack  = int(n_flows * attack_ratio)
    n_normal  = n_flows - n_attack
    rows      = []
    ts        = START_TIME

    for i in range(n_normal):
        ts   += timedelta(seconds=random.uniform(0.1, 5.0))
        hour  = ts.hour
        # Reduce traffic at night for realism
        if 1 <= hour <= 5 and random.random() < 0.7:
            continue
        gen = random.choice(NORMAL_GENERATORS)
        rows.append(gen(ts))

    for _ in range(n_attack):
        ts  += timedelta(seconds=random.uniform(0.01, 2.0))
        gen  = random.choice(ATTACK_GENERATORS)
        rows.append(gen(ts))

    random.shuffle(rows)

    fieldnames = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                  "protocol", "duration_sec", "src_bytes", "dst_bytes",
                  "packet_count", "failed_conns", "unique_ports", "label", "attack_type"]

    with open(output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    normal_count = sum(1 for r in rows if r["label"] == "normal")
    attack_count = sum(1 for r in rows if r["label"] == "attack")

    print(f"\n{'='*55}")
    print(f"  NetWatch — Traffic Simulation Complete")
    print(f"{'='*55}")
    print(f"  Output file    : {output}")
    print(f"  Total flows    : {len(rows)}")
    print(f"  Normal flows   : {normal_count} ({normal_count/len(rows)*100:.1f}%)")
    print(f"  Attack flows   : {attack_count} ({attack_count/len(rows)*100:.1f}%)")
    print(f"\n  Attack breakdown:")
    for atype in ["port_scan", "ddos", "exfiltration", "brute_force", "c2_beacon"]:
        n = sum(1 for r in rows if r["attack_type"] == atype)
        print(f"    {atype:<18}: {n}")
    print(f"{'='*55}\n")
    print(f"  Next step: python src/train.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch — Network traffic simulator")
    parser.add_argument("--flows",        type=int,   default=5000, help="Total flow records to generate")
    parser.add_argument("--attack-ratio", type=float, default=0.05, help="Fraction of flows that are attacks")
    parser.add_argument("--output",       default="data/network_flows.csv")
    args = parser.parse_args()
    simulate(n_flows=args.flows, attack_ratio=args.attack_ratio, output=args.output)
