from pathlib import Path

from pe_insight.input_validator import validate_input_file
from pe_insight.pe_parser import parse_pe_bytes, parse_pe_file
from pe_insight.risk_scoring import score_analysis
from pe_insight.string_extractor import (
    extract_and_classify_strings,
    extract_and_classify_strings_from_bytes,
)


def analyze_file(
    file_path: str | Path,
    *,
    max_string_scan_bytes: int | None = None,
    max_results_per_category: int = 50,
) -> tuple[Path, dict]:
    validated_path = validate_input_file(str(file_path))

    pe_summary = parse_pe_file(validated_path)
    string_data = extract_and_classify_strings(
        validated_path,
        max_scan_bytes=max_string_scan_bytes,
        max_results_per_category=max_results_per_category,
    )
    risk_data = score_analysis(pe_summary, string_data)

    result = {
        **pe_summary,
        **string_data,
        **risk_data,
    }

    return validated_path, result


def analyze_uploaded_bytes(
    file_bytes: bytes,
    file_name: str,
    *,
    max_string_scan_bytes: int | None = None,
    max_results_per_category: int = 25,
) -> dict:
    scan_bytes = file_bytes if max_string_scan_bytes is None else file_bytes[:max_string_scan_bytes]

    pe_summary = parse_pe_bytes(file_bytes, file_name)
    string_data = extract_and_classify_strings_from_bytes(
        scan_bytes,
        full_file_size=len(file_bytes),
        max_results_per_category=max_results_per_category,
    )
    risk_data = score_analysis(pe_summary, string_data)

    return {
        **pe_summary,
        **string_data,
        **risk_data,
    }