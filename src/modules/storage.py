import os
import json
from datetime import datetime


def save_crash(
    minimized_html,
    report,
    original_html,
    run_output,
    issue_reason,
    severity,
    signature,
    strategy_name,
    subsystem,
    worker_id,
    test_num,
    crashes_dir,
    novelty_skips=0,
    firefox_version="unknown"
):
    """Save crash artifacts and metadata; returns (crash_id, html_path, report_path)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    crash_id = f"{timestamp}_w{worker_id}_t{test_num}"

    crash_subdir = os.path.join(crashes_dir, crash_id)
    os.makedirs(crash_subdir, exist_ok=True)

    html_path = os.path.join(crash_subdir, "minimized.html")
    report_path = os.path.join(crash_subdir, "report.txt")
    original_path = os.path.join(crash_subdir, "original.html")
    output_path = os.path.join(crash_subdir, "output.txt")
    meta_path = os.path.join(crash_subdir, "meta.json")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(minimized_html)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    with open(original_path, "w", encoding="utf-8") as f:
        f.write(original_html)

    # Save full raw Firefox output (ASAN traces, assertions, etc.)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(run_output)

    meta = {
        "crash_id": crash_id,
        "timestamp": datetime.now().isoformat(),
        "worker_id": worker_id,
        "test_num": test_num,
        "issue_reason": issue_reason,
        "severity": severity,
        "status": "new",
        "html_file": "minimized.html",
        "report_file": "report.txt",
        "original_file": "original.html",
        "output_snippet": run_output[:2000],
        "signature": signature,
        "strategy_name": strategy_name,
        "subsystem": subsystem,
        "novelty_skips": novelty_skips,
        "firefox_version": firefox_version,
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return crash_id, html_path, report_path
