from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from uuid import uuid4

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from pe_insight.pe_parser import parse_pe_bytes
from pe_insight.report_writer import save_html_report, save_json_report
from pe_insight.risk_scoring import score_analysis
from pe_insight.string_extractor import extract_and_classify_strings_from_bytes
from pe_insight.view_models import build_visual_context

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".exe", ".dll"}
MAX_UPLOAD_MB = 25
WEB_STRING_SCAN_MB = 8

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

EXECUTOR = ThreadPoolExecutor(max_workers=2)
TASKS: dict[str, dict] = {}
TASK_LOCK = Lock()

STAGE_META = {
    "queued": {"label": "Queued for analysis", "progress": 8},
    "parsing": {"label": "Parsing PE headers", "progress": 28},
    "sections_imports": {"label": "Inspecting sections and imports", "progress": 48},
    "strings": {"label": "Extracting strings", "progress": 68},
    "scoring": {"label": "Calculating risk score", "progress": 82},
    "reports": {"label": "Generating reports", "progress": 94},
    "completed": {"label": "Analysis complete", "progress": 100},
    "failed": {"label": "Analysis failed", "progress": 100},
}


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def set_task(task_id: str, **updates) -> None:
    with TASK_LOCK:
        TASKS.setdefault(task_id, {})
        TASKS[task_id].update(updates)


def get_task(task_id: str) -> dict | None:
    with TASK_LOCK:
        task = TASKS.get(task_id)
        if not task:
            return None
        return dict(task)


def process_analysis_task(task_id: str, file_bytes: bytes, file_name: str) -> None:
    try:
        set_task(task_id, state="running", stage="parsing")

        pe_summary = parse_pe_bytes(file_bytes, file_name)

        set_task(task_id, stage="sections_imports")

        set_task(task_id, stage="strings")
        scan_bytes = file_bytes[: WEB_STRING_SCAN_MB * 1024 * 1024]
        string_data = extract_and_classify_strings_from_bytes(
            scan_bytes,
            full_file_size=len(file_bytes),
            max_results_per_category=25,
        )

        set_task(task_id, stage="scoring")
        risk_data = score_analysis(pe_summary, string_data)

        result = {
            **pe_summary,
            **string_data,
            **risk_data,
        }

        set_task(task_id, stage="reports")
        visual = build_visual_context(result)

        pseudo_source = Path(file_name)
        json_report_path = save_json_report(result, pseudo_source, OUTPUT_DIR)
        html_report_path = save_html_report(result, pseudo_source, OUTPUT_DIR)

        set_task(
            task_id,
            state="completed",
            stage="completed",
            result=result,
            visual=visual,
            file_name=file_name,
            json_report_name=json_report_path.name,
            html_report_name=html_report_path.name,
        )
    except Exception as exc:
        print(f"[ERROR] task {task_id} failed: {exc}")
        set_task(
            task_id,
            state="failed",
            stage="failed",
            error=str(exc),
        )


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(_error):
    return render_template(
        "index.html",
        error=f"File is too large. Maximum allowed size is {MAX_UPLOAD_MB} MB.",
    ), 413


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/submit", methods=["POST"])
def submit():
    uploaded_file = request.files.get("binary_file")

    if not uploaded_file or not uploaded_file.filename:
        return render_template("index.html", error="Please select an .exe or .dll file."), 400

    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        return render_template("index.html", error="Invalid filename."), 400

    if not allowed_file(original_name):
        return render_template("index.html", error="Only .exe and .dll files are allowed."), 400

    file_bytes = uploaded_file.read()

    if not file_bytes:
        return render_template("index.html", error="Uploaded file is empty."), 400

    task_id = uuid4().hex

    set_task(
        task_id,
        state="queued",
        stage="queued",
        file_name=original_name,
    )

    EXECUTOR.submit(process_analysis_task, task_id, file_bytes, original_name)

    return redirect(url_for("processing", task_id=task_id))


@app.route("/processing/<task_id>", methods=["GET"])
def processing(task_id: str):
    task = get_task(task_id)
    if not task:
        return render_template("index.html", error="Task not found."), 404

    return render_template(
        "processing.html",
        task_id=task_id,
        file_name=task.get("file_name", "binary"),
    )


@app.route("/task-status/<task_id>", methods=["GET"])
def task_status(task_id: str):
    task = get_task(task_id)
    if not task:
        return jsonify({"state": "missing"}), 404

    stage = task.get("stage", "queued")
    stage_info = STAGE_META.get(stage, STAGE_META["queued"])

    payload = {
        "state": task.get("state", "queued"),
        "stage": stage,
        "label": stage_info["label"],
        "progress": stage_info["progress"],
    }

    if task.get("state") == "completed":
        payload["redirect_url"] = url_for("result_page", task_id=task_id)

    if task.get("state") == "failed":
        payload["error"] = task.get("error", "Unknown error")

    return jsonify(payload)


@app.route("/result/<task_id>", methods=["GET"])
def result_page(task_id: str):
    task = get_task(task_id)
    if not task:
        return render_template("index.html", error="Task not found."), 404

    if task.get("state") != "completed":
        return redirect(url_for("processing", task_id=task_id))

    return render_template(
        "result.html",
        result=task["result"],
        visual=task["visual"],
        file_name=task["file_name"],
        json_report_name=task["json_report_name"],
        html_report_name=task["html_report_name"],
    )


@app.route("/reports/<path:filename>")
def serve_report(filename: str):
    return send_from_directory(str(OUTPUT_DIR), filename, as_attachment=False)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)