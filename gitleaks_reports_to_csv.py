import argparse
import csv
import json
import os
from pathlib import Path


def iter_leaks(payload):
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(payload, dict):
        for key in ("Leaks", "leaks", "findings", "Findings"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                return


def coerce_str(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def extract_row(leak):
    return {
        "File": coerce_str(leak.get("File") or leak.get("file")),
        "RuleID": coerce_str(leak.get("RuleID") or leak.get("rule_id") or leak.get("ruleID")),
        "Author": coerce_str(leak.get("Author") or leak.get("author")),
        "Date": coerce_str(leak.get("Date") or leak.get("date")),
        "Message": coerce_str(leak.get("Message") or leak.get("message")),
        "Entropy": coerce_str(leak.get("Entropy") if "Entropy" in leak else leak.get("entropy")),
        "Match": coerce_str(leak.get("Match") or leak.get("match")),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reports-dir",
        default=str(Path.cwd() / "reports"),
        help="Directory containing gitleaks JSON reports.",
    )
    parser.add_argument(
        "--output",
        default=str(Path.cwd() / "reports" / "gitleaks_findings.csv"),
        help="Output CSV path.",
    )
    parser.add_argument(
        "--pattern",
        default="*.json",
        help="Glob pattern for report files inside reports-dir.",
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    output_path = Path(args.output)

    if not reports_dir.exists() or not reports_dir.is_dir():
        raise SystemExit(f"reports dir not found: {reports_dir}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    columns = ["File", "RuleID", "Author", "Date", "Message", "Entropy", "Match"]

    total_files = 0
    total_rows = 0

    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for report_path in sorted(reports_dir.glob(args.pattern)):
            if not report_path.is_file():
                continue
            if report_path.name.endswith(".schema.json"):
                continue

            total_files += 1

            try:
                raw = report_path.read_text(encoding="utf-8")
                if not raw.strip():
                    continue
                payload = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                continue

            for leak in iter_leaks(payload):
                writer.writerow(extract_row(leak))
                total_rows += 1

    print(f"[+] scanned json files: {total_files}")
    print(f"[+] extracted rows: {total_rows}")
    print(f"[+] output: {output_path}")


if __name__ == "__main__":
    main()

