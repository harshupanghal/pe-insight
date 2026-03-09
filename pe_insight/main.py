import json
import sys

from pe_insight.analyzer import analyze_file
from pe_insight.report_writer import save_json_report


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m pe_insight.main <path_to_exe_or_dll>")
        sys.exit(1)

    file_arg = sys.argv[1]

    try:
        validated_path, result = analyze_file(file_arg)
        report_path = save_json_report(result, validated_path)

        print(json.dumps(result, indent=4))
        print(f"\n[OK] JSON report saved to: {report_path}")

    except Exception as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()