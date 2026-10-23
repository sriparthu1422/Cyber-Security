"""
scripts/generate_sample_data.py — Generate synthetic demonstration dataset.

Creates a reproducible CSV of synthetic network/authentication events
suitable for training and demonstrating the threat detection system.

IMPORTANT DISCLAIMER:
  This data is entirely SYNTHETIC. It does NOT represent real financial
  institution network traffic or real attack patterns. It was designed
  to demonstrate the detection pipeline's behavior, not to train a
  production security model.

Features generated:
  - failed_logins      : Failed authentication attempts (Poisson distributed)
  - bytes_in           : Inbound bytes (log-normal)
  - bytes_out          : Outbound bytes (log-normal)
  - connection_duration: Connection duration in seconds (exponential)
  - protocol           : Network protocol (categorical)
  - unusual_hour       : True if outside 8am-6pm business hours
  - port_number        : Destination port (from common list)
  - source_ip, dest_ip : Simulated IP addresses (RFC5737 documentation range)
  - label              : Ground truth (0=normal, 1=anomaly) — SYNTHETIC LABEL

Usage:
    python scripts/generate_sample_data.py [--rows 1000] [--output data/sample/network_events.csv]
"""
import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "ICMP"]
COMMON_PORTS = [80, 443, 22, 21, 53, 3389, 8080, 8443, 445, 25, 110, 143, 3306, 5432]
SUSPICIOUS_PORTS = [4444, 6667, 31337, 1337, 9999]  # Commonly associated with malware C2

# Use documentation IP ranges (RFC 5737 — never routed, safe for demos)
DOC_SUBNETS = ["192.0.2.", "198.51.100.", "203.0.113."]


def random_ip(rng: np.random.Generator) -> str:
    """Generate a random IP from documentation ranges (RFC 5737)."""
    subnet = rng.choice(DOC_SUBNETS)
    return f"{subnet}{rng.integers(1, 255)}"


def generate_normal_event(rng: np.random.Generator) -> dict:
    """Generate one normal network event."""
    hour = rng.integers(8, 18)  # Business hours: 8am-6pm
    return {
        "source_ip": random_ip(rng),
        "dest_ip": random_ip(rng),
        "protocol": rng.choice(PROTOCOLS, p=[0.30, 0.20, 0.15, 0.15, 0.05, 0.05, 0.05, 0.05]),
        "failed_logins": int(rng.poisson(0.3)),      # Rarely fails
        "bytes_in": float(np.exp(rng.normal(8, 1.5))),   # ~3KB typical
        "bytes_out": float(np.exp(rng.normal(7, 1.5))),  # ~1KB typical
        "connection_duration": float(rng.exponential(30)),  # Short-lived
        "unusual_hour": False,
        "port_number": int(rng.choice(COMMON_PORTS[:8])),   # Common ports
        "label": 0,
    }


def generate_anomalous_event(rng: np.random.Generator, anomaly_type: str = None) -> dict:
    """
    Generate one anomalous network event.

    Anomaly types:
    - brute_force: High failed login count + unusual hour
    - data_exfiltration: Massive bytes_out + unusual port
    - port_scan: Many ports, short duration
    - after_hours: Normal-looking but at unusual time with suspicious activity
    - c2_beacon: Small regular packets to suspicious port
    """
    rng_types = ["brute_force", "data_exfiltration", "after_hours", "c2_beacon", "port_scan"]
    if anomaly_type is None:
        anomaly_type = rng.choice(rng_types)

    event = generate_normal_event(rng)  # Start from normal base
    event["label"] = 1  # Override label

    if anomaly_type == "brute_force":
        event["failed_logins"] = int(rng.integers(15, 100))
        event["unusual_hour"] = bool(rng.random() > 0.3)
        event["port_number"] = int(rng.choice([22, 3389, 445]))
        event["connection_duration"] = float(rng.exponential(5))  # Short attempts
        event["bytes_in"] = float(np.exp(rng.normal(5, 0.5)))  # Small packets

    elif anomaly_type == "data_exfiltration":
        event["bytes_out"] = float(np.exp(rng.normal(14, 1.5)))  # Huge outbound
        event["unusual_hour"] = bool(rng.random() > 0.2)
        event["connection_duration"] = float(rng.exponential(300))  # Long running
        event["port_number"] = int(rng.choice(SUSPICIOUS_PORTS + [443, 80]))
        event["failed_logins"] = int(rng.poisson(1))

    elif anomaly_type == "after_hours":
        event["unusual_hour"] = True
        event["failed_logins"] = int(rng.integers(5, 20))
        event["port_number"] = int(rng.choice(SUSPICIOUS_PORTS + COMMON_PORTS[:3]))
        event["connection_duration"] = float(rng.exponential(120))

    elif anomaly_type == "c2_beacon":
        event["bytes_out"] = float(np.exp(rng.normal(4, 0.5)))   # Very small
        event["bytes_in"] = float(np.exp(rng.normal(4, 0.5)))    # Very small
        event["connection_duration"] = float(rng.exponential(2))  # Very short
        event["port_number"] = int(rng.choice(SUSPICIOUS_PORTS))
        event["unusual_hour"] = bool(rng.random() > 0.4)

    elif anomaly_type == "port_scan":
        event["bytes_in"] = float(np.exp(rng.normal(3, 0.3)))   # Tiny packets
        event["bytes_out"] = float(np.exp(rng.normal(3, 0.3)))
        event["connection_duration"] = float(rng.exponential(0.5))  # Extremely short
        event["port_number"] = int(rng.integers(1, 65535))  # Random port
        event["failed_logins"] = int(rng.integers(0, 3))

    return event


def generate_dataset(n_rows: int = 1000, anomaly_fraction: float = 0.12) -> pd.DataFrame:
    """
    Generate a complete synthetic dataset with normal and anomalous events.

    Args:
        n_rows: Total number of rows to generate
        anomaly_fraction: Fraction of rows that are anomalous (0.05 to 0.3)

    Returns:
        DataFrame with all features and ground-truth labels
    """
    rng = np.random.default_rng(RANDOM_SEED)

    n_anomalies = int(n_rows * anomaly_fraction)
    n_normal = n_rows - n_anomalies

    print(f"Generating {n_normal} normal events and {n_anomalies} anomalous events...")

    records = []

    # Normal events
    for _ in range(n_normal):
        records.append(generate_normal_event(rng))

    # Anomalous events (mixed types)
    anomaly_types = ["brute_force", "data_exfiltration", "after_hours", "c2_beacon", "port_scan"]
    for i in range(n_anomalies):
        anomaly_type = anomaly_types[i % len(anomaly_types)]
        records.append(generate_anomalous_event(rng, anomaly_type=anomaly_type))

    df = pd.DataFrame(records)

    # Shuffle so normal and anomalous rows are interleaved
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    return df


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic cybersecurity demonstration dataset."
    )
    parser.add_argument(
        "--rows", type=int, default=1000,
        help="Number of rows to generate (default: 1000)"
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent.parent / "data" / "sample" / "network_events.csv"),
        help="Output CSV file path"
    )
    parser.add_argument(
        "--anomaly-fraction", type=float, default=0.12,
        help="Fraction of anomalous events (default: 0.12)"
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = generate_dataset(n_rows=args.rows, anomaly_fraction=args.anomaly_fraction)

    df.to_csv(output_path, index=False)

    # Print summary
    normal_count = (df["label"] == 0).sum()
    anomaly_count = (df["label"] == 1).sum()
    print(f"\n{'='*60}")
    print(f"SYNTHETIC DATASET GENERATED")
    print(f"{'='*60}")
    print(f"Output file : {output_path}")
    print(f"Total rows  : {len(df)}")
    print(f"Normal      : {normal_count} ({normal_count/len(df):.1%})")
    print(f"Anomalous   : {anomaly_count} ({anomaly_count/len(df):.1%})")
    print(f"Columns     : {', '.join(df.columns)}")
    print(f"Random seed : {RANDOM_SEED}")
    print(f"\nDISCLAIMER: This data is entirely synthetic.")
    print(f"It does NOT represent real financial institution data.")
    print(f"{'='*60}\n")

    print("Sample rows:")
    print(df.head(3).to_string())


if __name__ == "__main__":
    main()
