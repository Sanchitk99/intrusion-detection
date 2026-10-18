import json
from pathlib import Path

from flask import Flask, render_template, jsonify, request, send_from_directory, abort
import pandas as pd
from agent import (
    get_live_metrics,
    get_attack_log,
    analyze_uploaded_csv,
    reset_agent_state,
    DEFAULT_METRICS
)

app = Flask(__name__)
DEMO_MODE = False
MAX_UPLOAD_ROWS = 100000
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BASE_DIR / "scripts"


def get_benchmark_data():
    """Consolidate structured evaluation benchmarks and cross-dataset results."""
    benchmarks = {
        "datasets": {},
        "cross_dataset_transfer": {},
        "comparability_disclaimer": (
            "Benchmark metrics across NSL-KDD, UNSW-NB15, and CICIDS2017 are not directly "
            "comparable because each dataset defines different feature spaces (connection summary counters "
            "vs packet window statistics vs flow duration timings), distinct network topologies, "
            "different attack distributions, and varying baseline noise levels."
        ),
        "policy": "ALERT_ONLY_NO_AUTO_BLOCK"
    }

    # 1. NSL-KDD
    nsl_path = BASE_DIR / "reports" / "nsl_kdd_evaluation" / "metrics.json"
    if nsl_path.exists():
        try:
            with open(nsl_path, "r", encoding="utf-8") as f:
                nsl_data = json.load(f)
            benchmarks["datasets"]["nsl_kdd"] = {
                "name": "NSL-KDD",
                "model": "Random Forest (100 Trees, class_weight='balanced_subsample')",
                "provenance": nsl_data.get("provenance", {}).get("provenance", "University of New Brunswick (UNB)"),
                "features_count": 41,
                "test_samples": nsl_data.get("samples", {}).get("test_rows", 29704),
                "total_samples": nsl_data.get("samples", {}).get("total_dataset_rows", 148517),
                "split_strategy": "Stratified 80/20 Holdout (Leak-Free Pipeline)",
                "accuracy": round(nsl_data.get("binary_metrics", {}).get("accuracy", 0.9946), 4),
                "precision": round(nsl_data.get("binary_metrics", {}).get("precision", 0.9952), 4),
                "recall": round(nsl_data.get("binary_metrics", {}).get("recall", 0.9938), 4),
                "f1": round(nsl_data.get("binary_metrics", {}).get("f1", 0.9945), 4),
                "macro_f1": round(nsl_data.get("multiclass_metrics", {}).get("macro_f1", 0.7539), 4),
                "balanced_accuracy": round(nsl_data.get("multiclass_metrics", {}).get("balanced_accuracy", 0.8826), 4),
                "false_positive_rate": round(nsl_data.get("binary_metrics", {}).get("false_positive_rate", 0.0045), 4),
                "roc_auc": round(nsl_data.get("binary_metrics", {}).get("roc_auc", 0.9998), 4),
                "pr_auc": round(nsl_data.get("binary_metrics", {}).get("pr_auc", 0.9998), 4),
                "minority_class_note": "U2R attack recall is 50.00% (or 42.86% in duplicate-aware group split); overall accuracy masks rare privilege escalation risk.",
                "caveats": "Contains 610 duplicate groups and 116 conflicting predictor rows in raw data; duplicate-aware split guarantees train/test isolation."
            }
        except Exception:
            pass

    # 2. UNSW-NB15
    unsw_path = BASE_DIR / "reports" / "unsw_nb15_evaluation" / "metrics.json"
    if unsw_path.exists():
        try:
            with open(unsw_path, "r", encoding="utf-8") as f:
                unsw_data = json.load(f)
            benchmarks["datasets"]["unsw_nb15"] = {
                "name": "UNSW-NB15",
                "model": "Random Forest (100 Trees, class_weight='balanced_subsample')",
                "provenance": unsw_data.get("provenance", {}).get("provenance", "Australian Centre for Cyber Security (ACCS)"),
                "features_count": 42,
                "test_samples": unsw_data.get("samples", {}).get("test_rows", 16467),
                "total_samples": unsw_data.get("samples", {}).get("total_dataset_rows", 82332),
                "split_strategy": "Stratified 80/20 Holdout (Leak-Free Pipeline)",
                "accuracy": round(unsw_data.get("binary_metrics", {}).get("accuracy", 0.8751), 4),
                "precision": round(unsw_data.get("binary_metrics", {}).get("precision", 0.9907), 4),
                "recall": round(unsw_data.get("binary_metrics", {}).get("recall", 0.9596), 4),
                "f1": round(unsw_data.get("binary_metrics", {}).get("f1", 0.9749), 4),
                "macro_f1": round(unsw_data.get("multiclass_metrics", {}).get("macro_f1", 0.7315), 4),
                "balanced_accuracy": round(unsw_data.get("multiclass_metrics", {}).get("balanced_accuracy", 0.7266), 4),
                "false_positive_rate": round(unsw_data.get("binary_metrics", {}).get("false_positive_rate", 0.0111), 4),
                "roc_auc": round(unsw_data.get("binary_metrics", {}).get("roc_auc", 0.9972), 4),
                "pr_auc": round(unsw_data.get("binary_metrics", {}).get("pr_auc", 0.9978), 4),
                "minority_class_note": "U2R recall: 47.37%; DoS precision: 40.21% due to subtle low-rate simulated flows.",
                "caveats": "Synthesized with IXIA PerfectStorm generator; high feature variance in TCP jitter and packet timings."
            }
        except Exception:
            pass

    # 3. CICIDS2017
    cic_path = BASE_DIR / "reports" / "cicids2017_evaluation" / "metrics.json"
    if cic_path.exists():
        try:
            with open(cic_path, "r", encoding="utf-8") as f:
                cic_data = json.load(f)
            benchmarks["datasets"]["cicids2017"] = {
                "name": "CICIDS2017",
                "model": "Random Forest (100 Trees, class_weight='balanced_subsample')",
                "provenance": cic_data.get("provenance", {}).get("provenance", "Canadian Institute for Cybersecurity (CIC)"),
                "features_count": 78,
                "test_samples": cic_data.get("samples", {}).get("test_rows", 57294),
                "total_samples": cic_data.get("samples", {}).get("total_dataset_rows", 286467),
                "split_strategy": "Stratified 80/20 Holdout (Deduplicated verification without Destination Port)",
                "accuracy": round(cic_data.get("binary_metrics", {}).get("accuracy", 0.9999), 4),
                "precision": round(cic_data.get("binary_metrics", {}).get("precision", 1.0000), 4),
                "recall": round(cic_data.get("binary_metrics", {}).get("recall", 0.9998), 4),
                "f1": round(cic_data.get("binary_metrics", {}).get("f1", 0.9999), 4),
                "macro_f1": round(cic_data.get("multiclass_metrics", {}).get("macro_f1", 0.9999), 4),
                "balanced_accuracy": round(cic_data.get("multiclass_metrics", {}).get("balanced_accuracy", 0.9999), 4),
                "false_positive_rate": round(cic_data.get("binary_metrics", {}).get("false_positive_rate", 0.0000), 4),
                "roc_auc": round(cic_data.get("binary_metrics", {}).get("roc_auc", 1.0000), 4),
                "pr_auc": round(cic_data.get("binary_metrics", {}).get("pr_auc", 1.0000), 4),
                "minority_class_note": "PortScan vector evaluated; near-perfect score reflects synthetic scan pattern uniformity.",
                "caveats": "Raw CSV contained 72,353 duplicates (25.26%). Deduplicated holdout verified: 0.999883 accuracy even without Destination Port."
            }
        except Exception:
            pass

    # 4. Cross-Dataset Transfer
    transfer_path = BASE_DIR / "reports" / "cross_dataset_evaluation" / "cross_dataset_transfer.json"
    if transfer_path.exists():
        try:
            with open(transfer_path, "r", encoding="utf-8") as f:
                t_data = json.load(f)
            experiments = t_data.get("transfer_experiments", [])
            if experiments:
                exp = experiments[0]
                benchmarks["cross_dataset_transfer"] = {
                    "source": exp.get("source_dataset", "NSL-KDD"),
                    "target": exp.get("target_dataset", "UNSW-NB15"),
                    "shared_features": exp.get("shared_features", []),
                    "in_domain_f1": round(exp.get("in_domain_nsl_f1", 0.9768), 4),
                    "cross_domain_f1": round(exp.get("cross_domain_unsw_f1", 0.0199), 4),
                    "f1_drop": round(exp.get("f1_drop", 0.9568), 4),
                    "conclusion": exp.get("conclusion", "Severe domain shift collapses transfer without dataset-specific calibration.")
                }
        except Exception:
            pass

    return benchmarks


@app.route("/", methods=["GET"])
def dashboard():
    return render_template(
        "dashboard.html",
        attack="Normal",
        risk="LOW",
        confidence=0.0,
        mode="Live Traffic",
        benchmarks=get_benchmark_data()
    )


@app.route("/about", methods=["GET"])
def about():
    return render_template("about.html", benchmarks=get_benchmark_data())


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return send_from_directory(
        str(BASE_DIR / "static"),
        "favicon.svg",
        mimetype="image/svg+xml"
    )


@app.route("/api/benchmarks", methods=["GET"])
@app.route("/benchmarks", methods=["GET"])
def benchmarks_api():
    return jsonify(get_benchmark_data())



@app.route("/health")
def health():
    from agent import get_system_health
    return jsonify(get_system_health())



@app.route("/history")
def history():
    return jsonify(get_attack_log())

@app.route("/metrics")
def metrics():
    global DEMO_MODE
    data = get_live_metrics(demo=DEMO_MODE)
    return jsonify(data)
@app.route("/toggle-demo", methods=["POST"])
def toggle_demo():
    global DEMO_MODE
    DEMO_MODE = not DEMO_MODE
    return jsonify({"demo": DEMO_MODE})


@app.route("/reset-stats", methods=["POST"])
def reset_stats():
    global DEMO_MODE
    DEMO_MODE = False
    reset_agent_state()
    return jsonify({
        "message": "Stats reset to live defaults.",
        "metrics": {**DEFAULT_METRICS},
        "history": get_attack_log()
    })


@app.route("/analyze-csv", methods=["POST"])
def analyze_csv():
    if "file" not in request.files:
        return jsonify({"error": "No CSV file was uploaded."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"error": "Please choose a CSV file."}), 400

    if not uploaded_file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are supported."}), 400

    try:
        dataframe = pd.read_csv(uploaded_file)
    except Exception:
        return jsonify({"error": "Could not read CSV. Please upload a valid CSV file."}), 400

    if len(dataframe) > MAX_UPLOAD_ROWS:
        return jsonify({
            "error": f"CSV has {len(dataframe)} rows. Maximum allowed is {MAX_UPLOAD_ROWS}."
        }), 400

    try:
        result = analyze_uploaded_csv(dataframe)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Failed to analyze CSV with current model."}), 500

    return jsonify(result)


@app.route("/download-log-script", methods=["GET"])
def download_log_script():
    script_name = "Activity_Generator.bat"
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        abort(404)

    return send_from_directory(
        directory=str(SCRIPTS_DIR),
        path=script_name,
        as_attachment=True,
        download_name=script_name,
        mimetype="text/plain; charset=utf-8"
    )


_drift_monitor = None

def _get_drift_monitor():
    global _drift_monitor
    if _drift_monitor is None:
        try:
            from scripts.drift_monitor import ModelDriftMonitor
            ref_path = BASE_DIR / "data" / "nsl_kdd.csv"
            if ref_path.exists():
                ref_df = pd.read_csv(ref_path, nrows=2500)
                _drift_monitor = ModelDriftMonitor(reference_data=ref_df)
        except Exception:
            _drift_monitor = None
    return _drift_monitor


@app.route("/alerts", methods=["GET"])
def alerts():
    return jsonify({
        "policy": "ALERT_ONLY_NO_AUTO_BLOCK",
        "description": "SOC analyst alert feed (auto-blocking disabled by design)",
        "alerts": get_attack_log()
    })


@app.route("/drift-status", methods=["GET"])
def drift_status():
    monitor = _get_drift_monitor()
    if monitor is None:
        return jsonify({
            "status": "UNAVAILABLE",
            "message": "Reference baseline dataset not loaded on host.",
            "drift_warning_level": "NOMINAL",
            "drifted_features_count": 0,
            "caveat": "Reference baseline required to compute Population Stability Index (PSI)."
        })
    try:
        from dataclasses import asdict
        sample_batch = monitor.reference_data.sample(n=min(300, len(monitor.reference_data)), random_state=42)
        report = monitor.evaluate_batch(sample_batch)
        return jsonify(asdict(report))
    except Exception as exc:
        return jsonify({
            "status": "ERROR",
            "message": str(exc),
            "drift_warning_level": "NOMINAL"
        }), 500


@app.route("/live-flows", methods=["GET"])
def live_flows():
    try:
        from scripts.flow_engine import LiveFlowTracker, classify_flow_records, get_feature_provenance_summary
        import joblib
        tracker = LiveFlowTracker()
        raw_flows = tracker.update_from_os_connections()
        pipeline_path = BASE_DIR / "artifacts" / "models" / "nsl_kdd_pipeline.joblib"
        if pipeline_path.exists():
            pipeline = joblib.load(pipeline_path)
            scored = classify_flow_records(raw_flows, pipeline)
            return jsonify({
                "status": "SUCCESS",
                "flow_count": len(scored),
                "active_model": {
                    "model_name": "RandomForestClassifier (100 Trees, Pipeline)",
                    "dataset": "NSL-KDD",
                    "artifact": "artifacts/models/nsl_kdd_pipeline.joblib",
                    "feature_count": 41,
                    "reported_accuracy": 0.9946,
                    "reported_macro_f1": 0.7539,
                    "reported_fpr": 0.0045,
                },
                "extraction_method": "OS Socket Table 5-Tuple Session Aggregation",
                "telemetry_level": "socket_session_metadata",
                "limitations": "Individual socket payload bytes and DPI flags (urgent, hot, num_compromised) default to 0; full packet capture requires Npcap/WinPcap kernel drivers.",
                "feature_provenance": get_feature_provenance_summary(),
                "flows": scored[:25],
                "action_policy": "ALERT_ONLY_NO_AUTO_BLOCK"
            })
        return jsonify({
            "status": "UNAVAILABLE",
            "message": "Trained pipeline artifact not found."
        }), 503
    except Exception as exc:
        return jsonify({"status": "ERROR", "message": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True)

