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
    novelty_skips=0
):
    """Save crash artifacts and metadata; returns (crash_id, html_path, report_path)."""
    os.makedirs(crashes_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    crash_id = f"{timestamp}_w{worker_id}_t{test_num}"

    html_path = os.path.join(crashes_dir, f"minimized_{crash_id}.html")
    report_path = os.path.join(crashes_dir, f"report_{crash_id}.txt")
    original_path = os.path.join(crashes_dir, f"original_{crash_id}.html")
    meta_path = os.path.join(crashes_dir, f"meta_{crash_id}.json")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(minimized_html)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    with open(original_path, "w", encoding="utf-8") as f:
        f.write(original_html)

    meta = {
        "crash_id": crash_id,
        "timestamp": datetime.now().isoformat(),
        "worker_id": worker_id,
        "test_num": test_num,
        "issue_reason": issue_reason,
        "severity": severity,
        "status": "new",
        "html_file": f"minimized_{crash_id}.html",
        "report_file": f"report_{crash_id}.txt",
        "original_file": f"original_{crash_id}.html",
        "output_snippet": run_output[:500],
        "signature": signature,
        "strategy_name": strategy_name,
        "subsystem": subsystem,
        "novelty_skips": novelty_skips,
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return crash_id, html_path, report_path
