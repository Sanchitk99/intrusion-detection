from flask import Flask, render_template, jsonify, request
import pandas as pd
from agent import get_live_metrics
from agent import get_attack_log
from agent import analyze_uploaded_csv

app = Flask(__name__)
DEMO_MODE = False
MAX_UPLOAD_ROWS = 100000
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

@app.route("/", methods=["GET"])
def dashboard():
    return render_template(
        "dashboard.html",
        attack="Normal",
        risk="LOW",
        confidence=0.0,
        mode="Live Traffic"
    )

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

if __name__ == "__main__":
    app.run(debug=True)
