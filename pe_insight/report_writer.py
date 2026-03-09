import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pe_insight.view_models import build_visual_context

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
REPORT_TEMPLATE_DIR = BASE_DIR / "report_templates"


def _ensure_output_dir(output_dir: str | Path = OUTPUT_DIR) -> Path:
    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def _build_report_base_name(source_file: Path) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{source_file.stem}_{timestamp}_report"


def save_json_report(result: dict, source_file: Path, output_dir: str | Path = OUTPUT_DIR) -> Path:
    output_path = _ensure_output_dir(output_dir)
    base_name = _build_report_base_name(source_file)
    report_path = output_path / f"{base_name}.json"

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    return report_path


def save_html_report(result: dict, source_file: Path, output_dir: str | Path = OUTPUT_DIR) -> Path:
    output_path = _ensure_output_dir(output_dir)
    base_name = _build_report_base_name(source_file)
    report_path = output_path / f"{base_name}.html"

    env = Environment(
        loader=FileSystemLoader(str(REPORT_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    template = env.get_template("standalone_report.html")
    rendered_html = template.render(
        result=result,
        visual=build_visual_context(result),
        file_name=source_file.name,
        score_angle=f"{result['risk_assessment']['risk_score'] * 3.6}deg",
    )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    return report_path