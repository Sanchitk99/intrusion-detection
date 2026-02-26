import psutil
import joblib
import numpy as np
import pandas as pd
import os
import random
import time
from collections import Counter
import socket
LAST_METRICS = {
    "attack": "Normal",
    "risk": "LOW",
    "confidence": 0.0,
    "src_rate": 0.0,
    "dst_rate": 0.0,
    "connections": 0,
    "packet_sent_rate": 0,
    "packet_recv_rate": 0,
    "top_source_ips": [],
    "top_destination_ports": [],
    "protocol_distribution": []

}
ATTACK_LOG = []
LAST_LOG_TIME = 0
LOG_INTERVAL = 10        # seconds
MAX_LOG_SIZE = 10        # only keep last 10 logs

# --------------------------------------------------
# Load trained artifacts
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(BASE_DIR, "model.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "scaler.pkl"))
attack_encoder = joblib.load(os.path.join(BASE_DIR, "attack_encoder.pkl"))
# --------------------------------------------------
# Globals for rate calculation
# --------------------------------------------------
PREV_STATS = None
# --------------------------------------------------
# Collect raw OS network stats
# --------------------------------------------------
def _extract_remote_ip(conn):
    raddr = getattr(conn, "raddr", None)
    if not raddr:
        return None

    if isinstance(raddr, tuple):
        return raddr[0] if raddr else None

    ip = getattr(raddr, "ip", None)
    if ip:
        return ip

    try:
        return raddr[0]
    except Exception:
        return None


def _extract_local_port(conn):
    laddr = getattr(conn, "laddr", None)
    if not laddr:
        return None

    if isinstance(laddr, tuple):
        return laddr[1] if len(laddr) > 1 else None

    port = getattr(laddr, "port", None)
    if port is not None:
        return port

    try:
        return laddr[1]
    except Exception:
        return None


def _extract_top_source_ips(conns, limit=5):
    counts = Counter()

    for conn in conns:
        ip = _extract_remote_ip(conn)

        if not ip or ip in {"127.0.0.1", "::1"}:
            continue

        counts[ip] += 1

    return [
        {"ip": ip, "connections": connection_count}
        for ip, connection_count in counts.most_common(limit)
    ]

def _extract_top_destination_ports(conns, limit=5):
    counts = Counter()

    for conn in conns:
        ip = _extract_remote_ip(conn)
        if not ip or ip in {"127.0.0.1", "::1"}:
            continue

        port = _extract_local_port(conn)
        if port is None:
            continue

        counts[int(port)] += 1

    return [
        {"port": port, "connections": connection_count}
        for port, connection_count in counts.most_common(limit)
    ]

def _extract_protocol_distribution(conns):
    counts = Counter({"TCP": 0, "UDP": 0, "OTHER": 0})

    for conn in conns:
        ip = _extract_remote_ip(conn)
        if not ip or ip in {"127.0.0.1", "::1"}:
            continue

        if conn.type == socket.SOCK_STREAM:
            counts["TCP"] += 1
        elif conn.type == socket.SOCK_DGRAM:
            counts["UDP"] += 1
        else:
            counts["OTHER"] += 1

    total = sum(counts.values())
    ordered = ["TCP", "UDP", "OTHER"]
    return [
        {
            "protocol": protocol,
            "connections": counts[protocol],
            "percentage": round((counts[protocol] / total) * 100, 1) if total else 0.0
        }
        for protocol in ordered
    ]


def get_raw_stats():
    net = psutil.net_io_counters()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        conns = []

    return {
        "src_bytes": net.bytes_sent,
        "dst_bytes": net.bytes_recv,
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
        "connections": len(conns),
        "top_source_ips": _extract_top_source_ips(conns),
        "top_destination_ports": _extract_top_destination_ports(conns),
        "protocol_distribution": _extract_protocol_distribution(conns),
        "timestamp": time.time()
    }


# --------------------------------------------------
# Convert raw counters → rates (CRITICAL)
# --------------------------------------------------
def compute_rates(current):
    global PREV_STATS

    if PREV_STATS is None:
        PREV_STATS = current
        return None

    delta_time = current["timestamp"] - PREV_STATS["timestamp"]
    if delta_time == 0:
        return None

    rates = {
    "src_rate": (current["src_bytes"] - PREV_STATS["src_bytes"]) / delta_time,
    "dst_rate": (current["dst_bytes"] - PREV_STATS["dst_bytes"]) / delta_time,
    "packet_sent_rate": (current["packets_sent"] - PREV_STATS["packets_sent"]) / delta_time,
    "packet_recv_rate": (current["packets_recv"] - PREV_STATS["packets_recv"]) / delta_time,
    "count": current["connections"],
    "srv_count": current["connections"]
}


    PREV_STATS = current
    return rates

# --------------------------------------------------
# Simulated attack behavior (SAFE DEMO MODE)
# --------------------------------------------------
def simulate_attack(features):
    features["dst_rate"] *= random.randint(50, 120)
    features["count"] *= random.randint(20, 60)
    features["srv_count"] *= random.randint(20, 60)
    return features

# --------------------------------------------------
# Build full NSL-KDD-shaped feature vector
# --------------------------------------------------
def build_feature_vector(features):
    FEATURE_COUNT = model.n_features_in_
    vector = np.zeros((1, FEATURE_COUNT))

    # Fill only if index exists (safe)
    if FEATURE_COUNT > 5:
        vector[0, 4] = features["src_rate"]
        vector[0, 5] = features["dst_rate"]

    if FEATURE_COUNT > 23:
        vector[0, 22] = features["count"]
        vector[0, 23] = features["srv_count"]

    if FEATURE_COUNT > 26:
        vector[0, 24] = 1 if features["count"] > 120 else 0
        vector[0, 25] = min(1.0, features["dst_rate"] / 1_000_000)
        vector[0, 26] = 1 if features["dst_rate"] > 2_000_000 else 0

    return vector


# --------------------------------------------------
# Risk interpretation (HUMAN-READABLE)
# --------------------------------------------------
def risk_level(prob):
    if prob < 60:
        return "LOW"
    elif prob < 80:
        return "MEDIUM"
    else:
        return "HIGH"

# --------------------------------------------------
# MAIN DETECTION FUNCTION
# --------------------------------------------------
def get_live_metrics(demo=False):
    global LAST_METRICS, ATTACK_LOG,LAST_LOG_TIME

    raw = get_raw_stats()
    features = compute_rates(raw)

    if features is None:
        LAST_METRICS["top_source_ips"] = raw["top_source_ips"]
        LAST_METRICS["top_destination_ports"] = raw["top_destination_ports"]
        LAST_METRICS["protocol_distribution"] = raw["protocol_distribution"]
        return LAST_METRICS

    if demo:
        features = simulate_attack(features)

    vector = build_feature_vector(features)
    feature_names = scaler.feature_names_in_
    vector_df = pd.DataFrame(vector, columns=feature_names)
    scaled = scaler.transform(vector_df)

    pred = model.predict(scaled)[0]
    prob = model.predict_proba(scaled)[0][pred] * 100
    attack_type = attack_encoder.inverse_transform([pred])[0]

    # Risk always defined
    risk = risk_level(prob)

    # Demo override
    if demo:
        prob = max(prob, 85.0)
        attack_type = "Fake Attack"
        risk = "HIGH"

    # Normal traffic override
    if prob < 70:
        attack_type = "Normal"

    LAST_METRICS = {
        "attack": attack_type,
        "risk": risk,
        "confidence": round(prob, 2),
        "src_rate": round(features["src_rate"], 2),
        "dst_rate": round(features["dst_rate"], 2),
        "connections": features["count"],
        "packet_sent_rate": round(features["packet_sent_rate"], 2),
        "packet_recv_rate": round(features["packet_recv_rate"], 2),
        "top_source_ips": raw["top_source_ips"],
        "top_destination_ports": raw["top_destination_ports"],
        "protocol_distribution": raw["protocol_distribution"]
    }

    # ✅ LOG ATTACK HISTORY
    now = time.time()
    if now - LAST_LOG_TIME >= LOG_INTERVAL:
        LAST_LOG_TIME = now

        ATTACK_LOG.append({
            "time": time.strftime("%H:%M:%S"),
            "attack": attack_type,
            "risk": risk,
            "confidence": round(prob, 2)
        })

        # Keep only last 10 logs
        ATTACK_LOG = ATTACK_LOG[-MAX_LOG_SIZE:]


    return LAST_METRICS

def get_system_health():
    # interval=0.1 forces an actual measurement
    cpu = psutil.cpu_percent(interval=0.1)

    return {
        "cpu": cpu,
        "ram": psutil.virtual_memory().percent,
        "net": psutil.net_io_counters().bytes_sent // 1024
    }

def get_attack_log():
    return ATTACK_LOG

from pynvml import *

def get_gpu_usage():
    try:
        nvmlInit()
        handle = nvmlDeviceGetHandleByIndex(0)
        util = nvmlDeviceGetUtilizationRates(handle)
        nvmlShutdown()
        return util.gpu
    except:
        return None


