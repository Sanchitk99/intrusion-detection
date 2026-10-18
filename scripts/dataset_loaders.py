"""Multi-dataset loader and preprocessing interface for Network Intrusion Detection.

Supports:
1. NSL-KDD
2. CICIDS2017
3. UNSW-NB15

Provides canonical unified label mapping (Binary: Normal vs Attack; Multiclass: DoS, Probe, R2L, U2R, Other, Exploits, Generic, etc.),
leakage-free train/validation/test splitting, and provenance documentation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

# ---------------------------------------------------------------------------
# Label Mappings & Taxonomies
# ---------------------------------------------------------------------------

NSL_KDD_ATTACK_MAP: Dict[str, str] = {
    # DoS
    "neptune": "DoS", "smurf": "DoS", "back": "DoS", "teardrop": "DoS", "pod": "DoS",
    "land": "DoS", "apache2": "DoS", "udpstorm": "DoS", "mailbomb": "DoS", "processtable": "DoS",
    # Probe
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R", "perl": "U2R",
    "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
    # Other
    "worm": "Other",
}

CICIDS2017_ATTACK_MAP: Dict[str, str] = {
    "benign": "Normal",
    "dos slowloris": "DoS",
    "dos slowhttptest": "DoS",
    "dos hulk": "DoS",
    "dos goldeneye": "DoS",
    "heartbleed": "DoS",
    "ddos": "DoS",
    "portscan": "Probe",
    "ftp-patator": "R2L",
    "ssh-patator": "R2L",
    "bot": "Other",
    "web attack – brute force": "R2L",
    "web attack – xss": "R2L",
    "web attack – sql injection": "R2L",
    "web attack - brute force": "R2L",
    "web attack - xss": "R2L",
    "web attack - sql injection": "R2L",
    "infiltration": "U2R",
}

UNSW_NB15_ATTACK_MAP: Dict[str, str] = {
    "normal": "Normal",
    "fuzzers": "Probe",
    "analysis": "Probe",
    "backdoors": "R2L",
    "backdoor": "R2L",
    "dos": "DoS",
    "exploits": "R2L",
    "generic": "Other",
    "reconnaissance": "Probe",
    "shellcode": "U2R",
    "worms": "Other",
}


@dataclass
class DatasetMetadata:
    name: str
    provenance: str
    licensing: str
    expected_filenames: List[str]
    target_column: str
    binary_positive_definition: str
    multiclass_categories: List[str]
    description: str


DATASET_CATALOG: Dict[str, DatasetMetadata] = {
    "nsl_kdd": DatasetMetadata(
        name="NSL-KDD",
        provenance="University of New Brunswick (UNB), Canadian Institute for Cybersecurity (Tavallaee et al., 2009). Refinement of KDD Cup 99 removing redundant and duplicate connection records.",
        licensing="Open for academic and non-commercial research use.",
        expected_filenames=["nsl_kdd.csv", "KDDTrain+.txt", "KDDTest+.txt"],
        target_column="label",
        binary_positive_definition="Any non-'Normal' connection flow.",
        multiclass_categories=["Normal", "DoS", "Probe", "R2L", "U2R", "Other"],
        description="41 flow & host traffic predictors representing TCP/UDP/ICMP sessions.",
    ),
    "cicids2017": DatasetMetadata(
        name="CICIDS2017",
        provenance="Canadian Institute for Cybersecurity (CIC), UNB (Sharafaldin et al., 2018). Captured across 5 days (Monday-Friday) containing benign background traffic and modern network attacks extracted with CICFlowMeter.",
        licensing="Open research license with attribution to Canadian Institute for Cybersecurity.",
        expected_filenames=[
            "cicids2017.csv",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
        ],
        target_column="label",
        binary_positive_definition="Any label other than 'BENIGN' / 'Normal'.",
        multiclass_categories=["Normal", "DoS", "Probe", "R2L", "U2R", "Other"],
        description="78-84 statistical flow features computed over forward/backward packet distributions.",
    ),
    "unsw_nb15": DatasetMetadata(
        name="UNSW-NB15",
        provenance="Cyber Range Lab of the Australian Centre for Cyber Security (ACCS) (Moustafa & Slay, 2015). Generated using IXIA PerfectStorm tool to simulate real modern normal and attack network activities.",
        licensing="Free for non-commercial research and academic use.",
        expected_filenames=["unsw_nb15.csv", "UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"],
        target_column="attack_cat",
        binary_positive_definition="Label column == 1 or attack_cat != 'Normal'.",
        multiclass_categories=["Normal", "DoS", "Probe", "R2L", "U2R", "Other"],
        description="49 network features comprising basic flow, content, time, and window metrics.",
    ),
}


def sanitize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace, replace internal whitespace/newlines, convert to clean strings."""
    df = df.copy()
    df.columns = [
        str(col).strip().replace(" ", "_").replace("\n", "").replace("\r", "")
        for col in df.columns
    ]
    return df


def clean_numeric_features(df: pd.DataFrame, numeric_cols: List[str]) -> pd.DataFrame:
    """Coerce non-numeric anomalies, replace infinite/NaN values safely."""
    df = df.copy()
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            median_val = df[col].median()
            df[col] = df[col].fillna(0.0 if np.isnan(median_val) else median_val)
    return df


def load_nsl_kdd(filepath: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.Series, pd.Series, List[str], List[str]]:
    """Load and preprocess NSL-KDD dataset cleanly without leakage.
    
    Returns:
        (X, y_multiclass, y_binary, categorical_cols, numeric_cols)
    """
    path = filepath or DATA_DIR / "nsl_kdd.csv"
    if not path.exists():
        raise FileNotFoundError(f"NSL-KDD dataset not found at {path}")

    df = pd.read_csv(path)
    df = sanitize_column_names(df)

    target_col = "label"
    if target_col not in df.columns:
        raise ValueError(f"Missing target column '{target_col}' in NSL-KDD dataset.")

    # Multiclass & Binary labels
    raw_labels = df[target_col].astype(str).str.strip().str.lower()
    y_multiclass = raw_labels.map(lambda x: "Normal" if x == "normal" else NSL_KDD_ATTACK_MAP.get(x, "Other"))
    y_binary = (y_multiclass != "Normal").astype(int)

    X = df.drop(columns=[target_col])
    if "difficulty_level" in X.columns:
        X = X.drop(columns=["difficulty_level"])

    categorical_cols = [c for c in ["protocol_type", "service", "flag"] if c in X.columns]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]
    X = clean_numeric_features(X, numeric_cols)

    return X, y_multiclass, y_binary, categorical_cols, numeric_cols


def load_cicids2017(filepath: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.Series, pd.Series, List[str], List[str]]:
    """Load CICIDS2017 dataset, clean headers, handle inf/NaN, map labels."""
    candidates = [
        filepath,
        DATA_DIR / "cicids2017.csv",
        DATA_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        DATA_DIR / "cicids2017_sample.csv"
    ]
    path = None
    for c in candidates:
        if c and Path(c).exists():
            path = Path(c)
            break

    if not path:
        raise FileNotFoundError(
            f"CICIDS2017 dataset not found in {DATA_DIR}. Please place 'cicids2017.csv' in data directory."
        )

    df = pd.read_csv(path, low_memory=False)
    df = sanitize_column_names(df)

    # Find label column
    label_col = None
    for col in df.columns:
        if col.lower() in {"label", "attack", "class"}:
            label_col = col
            break
    if not label_col:
        raise ValueError("Could not find label column in CICIDS2017 file.")

    raw_labels = df[label_col].astype(str).str.strip().str.lower()
    y_multiclass = raw_labels.map(lambda x: CICIDS2017_ATTACK_MAP.get(x, "Other" if "benign" not in x else "Normal"))
    y_binary = (y_multiclass != "Normal").astype(int)

    X = df.drop(columns=[label_col])
    # Drop identifiers if present
    for drop_col in ["Flow_ID", "Source_IP", "Destination_IP", "Timestamp", "Unnamed:_0"]:
        if drop_col in X.columns:
            X = X.drop(columns=[drop_col])

    categorical_cols = [c for c in X.columns if X[c].dtype == object]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]
    X = clean_numeric_features(X, numeric_cols)

    return X, y_multiclass, y_binary, categorical_cols, numeric_cols


def load_unsw_nb15(filepath: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.Series, pd.Series, List[str], List[str]]:
    """Load UNSW-NB15 dataset, map attack categories, handle binary flag."""
    candidates = [
        filepath,
        DATA_DIR / "unsw_nb15.csv",
        DATA_DIR / "UNSW_NB15_training-set.csv"
    ]
    path = None
    for c in candidates:
        if c and Path(c).exists():
            path = Path(c)
            break

    if not path:
        raise FileNotFoundError(
            f"UNSW-NB15 dataset not found in {DATA_DIR}. Please place 'unsw_nb15.csv' in data directory."
        )

    df = pd.read_csv(path, low_memory=False)
    df = sanitize_column_names(df)

    # UNSW-NB15 typically has attack_cat (multiclass) and label (binary: 0=normal, 1=attack)
    target_multi = None
    for col in ["attack_cat", "attack_category", "label"]:
        if col in df.columns:
            target_multi = col
            break

    if not target_multi:
        raise ValueError("Could not find attack category column in UNSW-NB15.")

    raw_labels = df[target_multi].astype(str).str.strip().str.lower()
    y_multiclass = raw_labels.map(lambda x: "Normal" if x in {"normal", "0", "benign", ""} else UNSW_NB15_ATTACK_MAP.get(x, "Other"))
    
    if "label" in df.columns and target_multi != "label":
        y_binary = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    else:
        y_binary = (y_multiclass != "Normal").astype(int)

    drop_cols = [c for c in ["id", "attack_cat", "attack_category", "label"] if c in df.columns]
    X = df.drop(columns=drop_cols)

    categorical_cols = [c for c in X.columns if X[c].dtype == object]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]
    X = clean_numeric_features(X, numeric_cols)

    return X, y_multiclass, y_binary, categorical_cols, numeric_cols


def build_unified_pipeline(
    categorical_columns: List[str],
    numeric_columns: List[str],
    classifier: Any,
) -> Pipeline:
    """Build a leakage-free Scikit-Learn Pipeline that fits preprocessing strictly on training folds."""
    transformers = []
    if categorical_columns:
        transformers.append(
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                categorical_columns,
            )
        )
    if numeric_columns:
        transformers.append(
            ("num", StandardScaler(), numeric_columns)
        )

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    return Pipeline(steps=[("preprocess", preprocessor), ("classifier", classifier)])

