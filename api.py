import os
import json
import shutil
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Firefox Fuzzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

CONFIG = load_config()
CRASHES_DIR = CONFIG["crashes_dir"]

class StatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None

class BulkStatusUpdate(BaseModel):
    crash_ids: list[str]
    status: str

class BulkDelete(BaseModel):
    crash_ids: list[str]


@app.get("/api/crashes")
def list_crashes():
    """List all crashes with metadata."""
    crashes = []
    if not os.path.exists(CRASHES_DIR):
        return {"crashes": []}

    for entry in os.listdir(CRASHES_DIR):
        crash_dir = os.path.join(CRASHES_DIR, entry)
        meta_path = os.path.join(crash_dir, "meta.json")
        if os.path.isdir(crash_dir) and os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                    crashes.append(meta)
            except (json.JSONDecodeError, OSError):
                continue

    crashes.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"crashes": crashes}


@app.get("/api/stats")
def get_stats():
    """Get fuzzer statistics with strategy and subsystem breakdowns."""
    crashes = list_crashes()["crashes"]

    by_strategy = {}
    for c in crashes:
        name = c.get("strategy_name", "unknown")
        if name not in by_strategy:
            by_strategy[name] = {"total": 0, "by_severity": {}}
        by_strategy[name]["total"] += 1
        sev = str(c.get("severity", 1))
        by_strategy[name]["by_severity"][sev] = by_strategy[name]["by_severity"].get(sev, 0) + 1

    by_subsystem = {}
    for c in crashes:
        sub = c.get("subsystem", "unknown")
        by_subsystem[sub] = by_subsystem.get(sub, 0) + 1

    stats = {
        "total": len(crashes),
        "new": sum(1 for c in crashes if c.get("status") == "new"),
        "awaiting_review": sum(1 for c in crashes if c.get("status") == "awaiting_review"),
        "verified": sum(1 for c in crashes if c.get("status") == "verified"),
        "ignored": sum(1 for c in crashes if c.get("status") == "ignored"),
        "submitted": sum(1 for c in crashes if c.get("status") == "submitted"),
        "by_severity": {i: sum(1 for c in crashes if c.get("severity") == i) for i in range(1, 6)},
        "by_strategy": by_strategy,
        "by_subsystem": by_subsystem,
        "by_verdict": {},
    }

    # Verdict breakdown (from verification daemon)
    for c in crashes:
        v = c.get("verdict")
        if v:
            stats["by_verdict"][v] = stats["by_verdict"].get(v, 0) + 1

    return stats


# Bulk routes MUST be defined before /{crash_id} routes
@app.patch("/api/crashes/bulk/status")
def bulk_update_status(update: BulkStatusUpdate):
    """Update status for multiple crashes at once."""
    updated = []
    errors = []
    for crash_id in update.crash_ids:
        crash_id = os.path.basename(crash_id)
        crash_dir = os.path.join(CRASHES_DIR, crash_id)
        meta_path = os.path.join(crash_dir, "meta.json")
        if not os.path.exists(meta_path):
            errors.append(crash_id)
            continue
        with open(meta_path, "r") as f:
            meta = json.load(f)
        meta["status"] = update.status
        meta["updated_at"] = datetime.now().isoformat()
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        updated.append(crash_id)
    return {"success": True, "updated": updated, "errors": errors}


@app.post("/api/crashes/bulk/delete")
def bulk_delete(request: BulkDelete):
    """Delete multiple crashes at once."""
    deleted = []
    errors = []
    for crash_id in request.crash_ids:
        crash_id = os.path.basename(crash_id)
        crash_dir = os.path.join(CRASHES_DIR, crash_id)
        if not os.path.isdir(crash_dir):
            errors.append(crash_id)
            continue
        shutil.rmtree(crash_dir)
        deleted.append(crash_id)
    return {"success": True, "deleted": deleted, "errors": errors}


@app.get("/api/crashes/{crash_id}")
def get_crash(crash_id: str):
    """Get full crash details including file contents."""
    crash_id = os.path.basename(crash_id)
    crash_dir = os.path.join(CRASHES_DIR, crash_id)
    meta_path = os.path.join(crash_dir, "meta.json")
    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="Crash not found")

    with open(meta_path, "r") as f:
        meta = json.load(f)

    html_path = os.path.join(crash_dir, meta["html_file"])
    report_path = os.path.join(crash_dir, meta["report_file"])
    original_path = os.path.join(crash_dir, meta.get("original_file", ""))
    verification_path = os.path.join(crash_dir, "verification_report.txt")
    output_path = os.path.join(crash_dir, "output.txt")

    html_content = ""
    report_content = ""
    original_content = ""
    verification_content = ""
    output_content = ""

    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()

    if os.path.exists(original_path):
        with open(original_path, "r", encoding="utf-8") as f:
            original_content = f.read()

    if os.path.exists(verification_path):
        with open(verification_path, "r", encoding="utf-8") as f:
            verification_content = f.read()

    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            output_content = f.read()

    return {
        "meta": meta,
        "html": html_content,
        "report": report_content,
        "original": original_content,
        "verification": verification_content,
        "output": output_content,
    }


@app.patch("/api/crashes/{crash_id}")
def update_crash(crash_id: str, update: StatusUpdate):
    """Update crash status."""
    crash_id = os.path.basename(crash_id)
    crash_dir = os.path.join(CRASHES_DIR, crash_id)
    meta_path = os.path.join(crash_dir, "meta.json")
    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="Crash not found")

    with open(meta_path, "r") as f:
        meta = json.load(f)

    meta["status"] = update.status
    if update.notes:
        meta["notes"] = update.notes
    meta["updated_at"] = datetime.now().isoformat()

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return {"success": True, "meta": meta}


@app.delete("/api/crashes/{crash_id}")
def delete_crash(crash_id: str):
    """Delete a crash and all its artifacts."""
    crash_id = os.path.basename(crash_id)
    crash_dir = os.path.join(CRASHES_DIR, crash_id)
    if not os.path.isdir(crash_dir):
        raise HTTPException(status_code=404, detail="Crash not found")

    shutil.rmtree(crash_dir)
    return {"success": True, "deleted": crash_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=6767)
