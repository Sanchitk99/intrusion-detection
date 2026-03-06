from pathlib import Path
import html
import re

from flask import Flask, render_template, jsonify, request, send_from_directory, abort
import pandas as pd
from agent import get_live_metrics
from agent import get_attack_log
from agent import analyze_uploaded_csv

app = Flask(__name__)
DEMO_MODE = False
MAX_UPLOAD_ROWS = 100000
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BASE_DIR / "scripts"


def _inline_markdown_to_html(text):
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def render_markdown_basic(markdown_text):
    lines = markdown_text.splitlines()
    chunks = []
    in_code_block = False
    in_unordered_list = False
    in_ordered_list = False

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_unordered_list:
                chunks.append("</ul>")
                in_unordered_list = False
            if in_ordered_list:
                chunks.append("</ol>")
                in_ordered_list = False

            if not in_code_block:
                chunks.append('<pre class="readme-code"><code>')
                in_code_block = True
            else:
                chunks.append("</code></pre>")
                in_code_block = False
            continue

        if in_code_block:
            chunks.append(html.escape(line))
            continue

        heading_match = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        bullet_match = re.match(r"^[-*]\s+(.*)$", stripped)
        ordered_match = re.match(r"^\d+\.\s+(.*)$", stripped)

        if stripped == "---":
            if in_unordered_list:
                chunks.append("</ul>")
                in_unordered_list = False
            if in_ordered_list:
                chunks.append("</ol>")
                in_ordered_list = False
            chunks.append("<hr>")
            continue

        if heading_match:
            if in_unordered_list:
                chunks.append("</ul>")
                in_unordered_list = False
            if in_ordered_list:
                chunks.append("</ol>")
                in_ordered_list = False

            level = min(len(heading_match.group(1)) + 1, 4)
            heading_text = _inline_markdown_to_html(heading_match.group(2))
            chunks.append(f"<h{level}>{heading_text}</h{level}>")
            continue

        if bullet_match:
            if in_ordered_list:
                chunks.append("</ol>")
                in_ordered_list = False
            if not in_unordered_list:
                chunks.append("<ul>")
                in_unordered_list = True
            chunks.append(f"<li>{_inline_markdown_to_html(bullet_match.group(1))}</li>")
            continue

        if ordered_match:
            if in_unordered_list:
                chunks.append("</ul>")
                in_unordered_list = False
            if not in_ordered_list:
                chunks.append("<ol>")
                in_ordered_list = True
            chunks.append(f"<li>{_inline_markdown_to_html(ordered_match.group(1))}</li>")
            continue

        if stripped == "":
            if in_unordered_list:
                chunks.append("</ul>")
                in_unordered_list = False
            if in_ordered_list:
                chunks.append("</ol>")
                in_ordered_list = False
            continue

        if in_unordered_list:
            chunks.append("</ul>")
            in_unordered_list = False
        if in_ordered_list:
            chunks.append("</ol>")
            in_ordered_list = False

        chunks.append(f"<p>{_inline_markdown_to_html(stripped)}</p>")

    if in_unordered_list:
        chunks.append("</ul>")
    if in_ordered_list:
        chunks.append("</ol>")
    if in_code_block:
        chunks.append("</code></pre>")

    return "\n".join(chunks)

@app.route("/", methods=["GET"])
def dashboard():
    return render_template(
        "dashboard.html",
        attack="Normal",
        risk="LOW",
        confidence=0.0,
        mode="Live Traffic"
    )


@app.route("/about", methods=["GET"])
def about():
    readme_path = BASE_DIR / "README.md"
    if readme_path.exists():
        readme_text = readme_path.read_text(encoding="utf-8")
        readme_html = render_markdown_basic(readme_text)
    else:
        readme_html = "<p>README.md was not found in the project root.</p>"

    return render_template(
        "about.html",
        readme_html=readme_html
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


@app.route("/download-log-script", methods=["GET"])
def download_log_script():
    script_name = "run_export_activity.bat"
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


if __name__ == "__main__":
    app.run(debug=True)
