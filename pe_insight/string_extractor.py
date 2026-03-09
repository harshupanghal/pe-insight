from __future__ import annotations

import re
from pathlib import Path


MIN_STRING_LENGTH = 4
DEFAULT_MAX_RESULTS_PER_CATEGORY = 50

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WINDOWS_PATH_REGEX = re.compile(
    r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
)
REGISTRY_REGEX = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n]+",
    re.IGNORECASE,
)
COMMAND_HINT_REGEX = re.compile(
    r"\b(?:cmd\.exe|powershell(?:\.exe)?|rundll32\.exe|reg\.exe|netsh(?:\.exe)?|schtasks(?:\.exe)?)\b",
    re.IGNORECASE,
)


def _safe_decode(data: bytes, encoding: str) -> str | None:
    try:
        return data.decode(encoding, errors="ignore")
    except Exception:
        return None


def _read_file_bytes(file_path: Path, max_scan_bytes: int | None = None) -> tuple[bytes, int]:
    file_size = file_path.stat().st_size

    with open(file_path, "rb") as f:
        if max_scan_bytes is None:
            return f.read(), file_size
        return f.read(max_scan_bytes), file_size


def extract_ascii_strings_from_bytes(data: bytes, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
    matches = pattern.findall(data)
    return [match.decode("ascii", errors="ignore") for match in matches]


def extract_utf16le_strings_from_bytes(data: bytes, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}")
    matches = pattern.findall(data)

    decoded_strings = []
    for match in matches:
        decoded = _safe_decode(match, "utf-16le")
        if decoded:
            decoded_strings.append(decoded)

    return decoded_strings


def _deduplicate_preserve_order(values: list[str]) -> list[str]:
    seen = set()
    result = []

    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)

    return result


def _limit_list(values: list[str], max_items: int) -> list[str]:
    return values[:max_items]


def classify_interesting_strings(
    strings: list[str],
    max_results_per_category: int = DEFAULT_MAX_RESULTS_PER_CATEGORY,
) -> dict:
    categorized = {
        "url": [],
        "ipv4": [],
        "windows_path": [],
        "registry_key": [],
        "command_hint": [],
    }

    for value in strings:
        if URL_REGEX.search(value):
            categorized["url"].append(value)

        if IPV4_REGEX.search(value):
            categorized["ipv4"].append(value)

        if WINDOWS_PATH_REGEX.search(value):
            categorized["windows_path"].append(value)

        if REGISTRY_REGEX.search(value):
            categorized["registry_key"].append(value)

        if COMMAND_HINT_REGEX.search(value):
            categorized["command_hint"].append(value)

    for key in categorized:
        categorized[key] = _limit_list(
            _deduplicate_preserve_order(categorized[key]),
            max_results_per_category,
        )

    return categorized


def extract_and_classify_strings_from_bytes(
    data: bytes,
    *,
    full_file_size: int | None = None,
    max_results_per_category: int = DEFAULT_MAX_RESULTS_PER_CATEGORY,
) -> dict:
    scanned_bytes = len(data)
    if full_file_size is None:
        full_file_size = scanned_bytes

    ascii_strings = extract_ascii_strings_from_bytes(data)
    utf16_strings = extract_utf16le_strings_from_bytes(data)

    combined_strings = _deduplicate_preserve_order(ascii_strings + utf16_strings)
    interesting = classify_interesting_strings(
        combined_strings,
        max_results_per_category=max_results_per_category,
    )

    strings_summary = {
        "ascii_string_count": len(ascii_strings),
        "utf16le_string_count": len(utf16_strings),
        "combined_unique_string_count": len(combined_strings),
        "scanned_bytes": scanned_bytes,
        "full_file_size": full_file_size,
        "scan_truncated": scanned_bytes < full_file_size,
        "interesting_counts": {
            key: len(values) for key, values in interesting.items()
        },
    }

    return {
        "strings_summary": strings_summary,
        "interesting_strings": interesting,
    }


def extract_and_classify_strings(
    file_path: Path,
    max_scan_bytes: int | None = None,
    max_results_per_category: int = DEFAULT_MAX_RESULTS_PER_CATEGORY,
) -> dict:
    data, full_file_size = _read_file_bytes(file_path, max_scan_bytes=max_scan_bytes)
    return extract_and_classify_strings_from_bytes(
        data,
        full_file_size=full_file_size,
        max_results_per_category=max_results_per_category,
    )