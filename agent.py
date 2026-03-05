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
encoders = joblib.load(os.path.join(BASE_DIR, "encoders.pkl"))
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


PC_ACTIVITY_COLUMNS = {
    "sample_time",
    "protocol",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "state",
    "owning_process"
}

SERVICE_PORT_MAP = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain_u",
    67: "dhcp",
    68: "dhcp",
    69: "tftp_u",
    80: "http",
    110: "pop_3",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
    139: "netbios_ssn",
    143: "imap4",
    161: "snmp",
    389: "ldap",
    443: "http_443",
    445: "microsoft_ds",
    993: "imap4",
    995: "pop_3",
    1433: "sql_net",
    3306: "mysql",
    3389: "remote_job",
    5432: "postgresql"
}

STATE_TO_FLAG_MAP = {
    "ESTABLISHED": "SF",
    "SYN_SENT": "S0",
    "SYN_RECEIVED": "S0",
    "LISTEN": "S0",
    "TIME_WAIT": "S1",
    "FIN_WAIT_1": "S1",
    "FIN_WAIT_2": "S1",
    "CLOSE_WAIT": "S1",
    "CLOSING": "S1",
    "LAST_ACK": "S1",
    "CLOSED": "REJ"
}


def _normalize_columns(dataframe):
    normalized = dataframe.copy()
    normalized.columns = [str(column).strip() for column in normalized.columns]
    return normalized


def _looks_like_pc_activity_csv(dataframe):
    normalized = {str(column).strip().lower() for column in dataframe.columns}
    return {"protocol", "local_port"}.issubset(normalized)


def _map_service_from_port(port_value):
    try:
        port = int(float(port_value))
    except (TypeError, ValueError):
        return "other"

    return SERVICE_PORT_MAP.get(port, "other")


def _map_flag_from_state(state_value):
    state = str(state_value).strip().upper()
    if not state:
        return "S0"
    return STATE_TO_FLAG_MAP.get(state, "S0")


def _build_features_from_pc_activity(dataframe, expected_columns):
    if not _looks_like_pc_activity_csv(dataframe):
        return None

    raw = dataframe.copy()
    raw.columns = [str(column).strip().lower() for column in raw.columns]

    if "protocol" not in raw.columns:
        return None

    if "local_address" not in raw.columns:
        raw["local_address"] = ""
    if "remote_address" not in raw.columns:
        raw["remote_address"] = ""
    if "remote_port" not in raw.columns:
        raw["remote_port"] = 0
    if "state" not in raw.columns:
        raw["state"] = ""

    local_port_num = pd.to_numeric(raw["local_port"], errors="coerce").fillna(0).astype(int)
    remote_port_num = pd.to_numeric(raw["remote_port"], errors="coerce").fillna(0).astype(int)
    remote_address = raw["remote_address"].fillna("").astype(str)

    remote_key = remote_address.replace("", "unknown")
    remote_count = remote_key.map(remote_key.value_counts()).astype("float64")
    service_count = local_port_num.map(local_port_num.value_counts()).astype("float64")

    same_srv_rate = (service_count / remote_count.replace(0, np.nan)).fillna(0).clip(0, 1)
    diff_srv_rate = (1 - same_srv_rate).clip(0, 1)
    unique_remote_per_service = pd.Series(
        remote_key.groupby(local_port_num).transform("nunique"),
        index=raw.index,
        dtype="float64"
    )
    srv_diff_host_rate = (
        unique_remote_per_service / service_count.replace(0, np.nan)
    ).fillna(0).clip(0, 1)

    land = (
        (raw["local_address"].fillna("").astype(str) == remote_address) &
        (local_port_num == remote_port_num)
    ).astype("float64")

    syn_states = {"SYN_SENT", "SYN_RECEIVED", "LISTEN"}
    state_upper = raw["state"].fillna("").astype(str).str.upper()
    serror = state_upper.isin(syn_states).astype("float64")
    rerror = state_upper.str.contains("RESET|CLOSED", regex=True).astype("float64")
    logged_in = state_upper.eq("ESTABLISHED").astype("float64")

    prepared = pd.DataFrame(index=raw.index)

    if "protocol_type" in expected_columns:
        prepared["protocol_type"] = raw["protocol"].fillna("tcp").astype(str).str.lower()
    if "service" in expected_columns:
        prepared["service"] = remote_port_num.map(_map_service_from_port)
    if "flag" in expected_columns:
        prepared["flag"] = raw["state"].map(_map_flag_from_state)

    derived_numeric = {
        "duration": 0.0,
        "src_bytes": 0.0,
        "dst_bytes": 0.0,
        "land": land,
        "wrong_fragment": 0.0,
        "urgent": 0.0,
        "hot": 0.0,
        "num_failed_logins": 0.0,
        "logged_in": logged_in,
        "num_compromised": 0.0,
        "root_shell": 0.0,
        "su_attempted": 0.0,
        "num_root": 0.0,
        "num_file_creations": 0.0,
        "num_shells": 0.0,
        "num_access_files": 0.0,
        "num_outbound_cmds": 0.0,
        "is_host_login": 0.0,
        "is_guest_login": 0.0,
        "count": remote_count,
        "srv_count": service_count,
        "serror_rate": serror,
        "srv_serror_rate": serror,
        "rerror_rate": rerror,
        "srv_rerror_rate": rerror,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": remote_count,
        "dst_host_srv_count": service_count,
        "dst_host_same_srv_rate": same_srv_rate,
        "dst_host_diff_srv_rate": diff_srv_rate,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_serror_rate": serror,
        "dst_host_srv_serror_rate": serror,
        "dst_host_rerror_rate": rerror,
        "dst_host_srv_rerror_rate": rerror
    }

    for column_name, value in derived_numeric.items():
        if column_name not in expected_columns:
            continue

        if np.isscalar(value):
            prepared[column_name] = float(value)
        else:
            prepared[column_name] = value

    return prepared


def _coerce_uploaded_column(series, column_name):
    if column_name in encoders:
        encoder = encoders[column_name]
        class_to_index = {str(label): idx for idx, label in enumerate(encoder.classes_)}
        converted = []

        for value in series:
            if pd.isna(value):
                converted.append(-1.0)
                continue

            try:
                numeric = float(value)
                if np.isfinite(numeric):
                    converted.append(float(int(numeric)))
                    continue
            except (TypeError, ValueError):
                pass

            converted.append(float(class_to_index.get(str(value).strip(), -1)))

        return pd.Series(converted, index=series.index, dtype="float64")

    numeric = pd.to_numeric(series, errors="coerce")
    return numeric.fillna(0.0).astype("float64")


def analyze_uploaded_csv(dataframe, preview_limit=30):
    if dataframe is None or dataframe.empty:
        raise ValueError("Uploaded CSV is empty.")

    original = _normalize_columns(dataframe)
    expected_columns = list(scaler.feature_names_in_)
    pc_features = _build_features_from_pc_activity(original, expected_columns)

    if pc_features is not None:
        source_dataframe = pc_features
        source_mode = "pc_activity"
        ignored_columns = [
            column for column in original.columns
            if column.strip().lower() not in PC_ACTIVITY_COLUMNS
        ]
    else:
        source_dataframe = original
        source_mode = "model_features"
        ignored_columns = [column for column in original.columns if column not in expected_columns]

    prepared = pd.DataFrame(index=source_dataframe.index)

    for column in expected_columns:
        if column in source_dataframe.columns:
            prepared[column] = _coerce_uploaded_column(source_dataframe[column], column)
        else:
            prepared[column] = 0.0

    prepared = prepared.astype("float64")
    scaled = scaler.transform(prepared)

    predictions = model.predict(scaled)
    labels = attack_encoder.inverse_transform(predictions)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(scaled).max(axis=1) * 100
    else:
        probabilities = np.zeros(len(labels))

    results = pd.DataFrame({
        "row": np.arange(1, len(labels) + 1),
        "prediction": labels,
        "confidence": np.round(probabilities, 2)
    })
    results["risk"] = results["confidence"].apply(risk_level)

    attack_breakdown = results["prediction"].value_counts().to_dict()
    missing_columns = [column for column in expected_columns if column not in source_dataframe.columns]

    return {
        "input_mode": source_mode,
        "rows_processed": int(len(results)),
        "high_risk_rows": int((results["risk"] == "HIGH").sum()),
        "attack_breakdown": attack_breakdown,
        "missing_columns": missing_columns,
        "ignored_columns": ignored_columns,
        "preview": results.head(preview_limit).to_dict(orient="records")
    }

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


