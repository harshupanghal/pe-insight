from __future__ import annotations


def _humanize_key(value: str) -> str:
    return value.replace("_", " ").strip().title()


def _build_bar_items(mapping: dict[str, int]) -> list[dict]:
    items = [
        {
            "key": key,
            "label": _humanize_key(key),
            "value": int(raw_value or 0),
        }
        for key, raw_value in mapping.items()
    ]

    max_value = max((item["value"] for item in items), default=0)

    for item in items:
        if item["value"] <= 0 or max_value == 0:
            item["width"] = 0
        else:
            item["width"] = max(10, round((item["value"] / max_value) * 100))

    return items


def build_visual_context(result: dict) -> dict:
    imports = result.get("imports", [])
    suspicious_imports = result.get("suspicious_imports", [])
    sections = result.get("sections", [])
    strings_summary = result.get("strings_summary", {})
    interesting_counts = strings_summary.get("interesting_counts", {})
    indicator_counts = result.get("risk_assessment", {}).get("indicator_counts", {})

    section_entropy_chart = []
    for section in sorted(sections, key=lambda item: item.get("entropy", 0), reverse=True)[:8]:
        entropy = float(section.get("entropy", 0) or 0)
        section_entropy_chart.append(
            {
                "label": section.get("name") or "unnamed",
                "value": entropy,
                "width": 0 if entropy <= 0 else max(10, round((min(entropy, 8) / 8) * 100)),
                "level": section.get("entropy_level", "low"),
            }
        )

    imported_function_count = sum(int(entry.get("import_count", 0) or 0) for entry in imports)

    overview_metrics = [
        {"label": "Imported DLLs", "value": len(imports)},
        {"label": "Imported APIs", "value": imported_function_count},
        {"label": "Suspicious Imports", "value": len(suspicious_imports)},
        {"label": "Anomaly Hints", "value": len(result.get("anomaly_summary", []))},
    ]

    return {
        "section_entropy_chart": section_entropy_chart,
        "indicator_chart": _build_bar_items(indicator_counts),
        "string_chart": _build_bar_items(interesting_counts),
        "overview_metrics": overview_metrics,
        "top_suspicious_imports": suspicious_imports[:10],
    }