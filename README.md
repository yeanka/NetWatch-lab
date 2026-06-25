# 🛡️ NetWatch — Network Anomaly Detection with Machine Learning

> A beginner-friendly ML + cybersecurity project that simulates real network traffic, engineers meaningful features, and trains an Isolation Forest model to automatically flag anomalous connections — no labelled attack data required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.3-orange)
![Method](https://img.shields.io/badge/Method-Unsupervised%20ML-purple)
![Domain](https://img.shields.io/badge/Domain-Network%20Security-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 What This Project Does

Traditional intrusion detection relies on known attack signatures — but what about attacks that have never been seen before? This project builds an **unsupervised anomaly detector** that learns what *normal* network traffic looks like and automatically flags anything that deviates from it.

No labelled attack examples needed. The model learns normal, then hunts for the abnormal.

### Anomaly Types Detected

| Attack Type | Description |
|-------------|-------------|
| Port Scan | Rapid connections to many ports from one IP |
| DDoS Flood | Abnormally high packet volume in a short window |
| Data Exfiltration | Large outbound data transfers at unusual hours |
| Brute Force | Repeated failed auth attempts to a single host |
| C2 Beacon | Regular low-volume connections at suspicious intervals |

---

## 🗂️ Repository Structure

```
netwatch/
├── README.md
├── requirements.txt
│
├── data/
│   ├── simulate_traffic.py      ← Generates synthetic network flow data
│   └── network_flows.csv        ← Generated dataset (created at runtime)
│
├── src/
│   ├── features.py              ← Feature engineering from raw flows
│   ├── train.py                 ← Isolation Forest training pipeline
│   ├── detect.py                ← Real-time anomaly detection engine
│   └── explain.py               ← Human-readable alert explanations
│
├── models/
│   └── (saved model after training)
│
├── dashboard/
│   └── netwatch_dashboard.html  ← Interactive browser dashboard
│
├── reports/
│   └── FINDINGS_REPORT.md       ← Research findings and analysis
│
└── docs/
    ├── BEGINNER_GUIDE.md        ← Step-by-step setup guide
    └── HOW_IT_WORKS.md          ← Plain-English explanation of the ML
```

---

## 🚀 Quick Start

```bash
# 1. Clone and install
git clone https://github.com/YOUR_USERNAME/netwatch.git
cd netwatch
pip install -r requirements.txt

# 2. Generate synthetic traffic data
python data/simulate_traffic.py

# 3. Train the anomaly detector
python src/train.py

# 4. Run detection on new traffic
python src/detect.py --input data/network_flows.csv

# 5. Open the dashboard
open dashboard/netwatch_dashboard.html
```

---

## 📊 Model Results

| Metric | Value |
|--------|-------|
| Algorithm | Isolation Forest |
| Training samples | 5,000 normal flows |
| Contamination rate | 5% (tunable) |
| Detection rate (simulated attacks) | ~94% |
| False positive rate | ~3% |
| Inference time per flow | < 1ms |

---

## 🔬 Features Engineered

| Feature | Type | Security Meaning |
|---------|------|-----------------|
| Bytes per second | Float | Exfiltration has abnormally high throughput |
| Packet rate | Float | DDoS floods have extreme packet counts |
| Connection duration | Float | Port scans are very short-lived |
| Unique ports contacted | Int | Port scanning contacts many ports |
| Failed connection ratio | Float | Brute force has high failure rates |
| Hour of day | Int | Off-hours traffic is suspicious |
| Protocol (encoded) | Int | Unusual protocols signal tunnelling |
| Src/dst byte ratio | Float | Exfiltration has lopsided ratios |
| Inter-arrival time | Float | C2 beacons are abnormally regular |
| Connection frequency | Float | High frequency from one IP = scan |

---

## 🧠 Why Unsupervised Learning?

```
Supervised ML:          Unsupervised ML (this project):
────────────────        ──────────────────────────────
Needs labelled          Only needs normal traffic
attack examples         
                        Learns the "shape" of normal
Misses novel            
(zero-day) attacks      Flags ANY deviation — including
                        attacks never seen before
Requires constant       
signature updates       Self-adapting to your network
```

Isolation Forest works by randomly partitioning data — anomalies are isolated in fewer cuts because they are statistically different from the dense normal cluster.

---

## ⚠️ Disclaimer

This project uses **synthetic/simulated** network data for educational purposes. Do not run this tool against networks you do not own or have explicit permission to monitor.

---

## 📚 References

- [Isolation Forest Paper — Liu, Ting, Zhou (2008)](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)
- [CICIDS 2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [NIST Guide to Intrusion Detection](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf)
- [Scikit-learn IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

---

## 👤 Author

**[Your Name]** | Cybersecurity & ML Researcher  
📧 your@email.com | [GitHub](https://github.com) | [LinkedIn](https://linkedin.com)

*Part of my cybersecurity + ML portfolio for graduate school applications.*
