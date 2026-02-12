from flask import Flask, render_template, request, jsonify
from agent import get_live_metrics
from agent import get_attack_log

app = Flask(__name__)
DEMO_MODE = False

@app.route("/", methods=["GET"])
def dashboard():
    return render_template(
        "dashboard.html",
        attack="Normal",
        risk="LOW",
        confidence=0.0,
        mode="Live Traffic"
    )

THRESHOLD = 70
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

if __name__ == "__main__":
    app.run(debug=True)
