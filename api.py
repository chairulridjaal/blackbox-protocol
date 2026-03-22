import os
import json
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

@app.get("/api/crashes")
def list_crashes():
    """List all crashes with metadata."""
    crashes = []
    if not os.path.exists(CRASHES_DIR):
        return {"crashes": []}

    for filename in os.listdir(CRASHES_DIR):
        if filename.startswith("meta_") and filename.endswith(".json"):
            meta_path = os.path.join(CRASHES_DIR, filename)
            with open(meta_path, "r") as f:
                meta = json.load(f)
                crashes.append(meta)

    # Sort by timestamp descending
    crashes.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"crashes": crashes}

@app.get("/api/crashes/{crash_id}")
def get_crash(crash_id: str):
    """Get full crash details including file contents."""
    meta_path = os.path.join(CRASHES_DIR, f"meta_{crash_id}.json")
    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="Crash not found")

    with open(meta_path, "r") as f:
        meta = json.load(f)

    # Load file contents
    html_path = os.path.join(CRASHES_DIR, meta["html_file"])
    report_path = os.path.join(CRASHES_DIR, meta["report_file"])
    original_path = os.path.join(CRASHES_DIR, meta.get("original_file", ""))

    html_content = ""
    report_content = ""
    original_content = ""

    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()

    if os.path.exists(original_path):
        with open(original_path, "r", encoding="utf-8") as f:
            original_content = f.read()

    return {
        "meta": meta,
        "html": html_content,
        "report": report_content,
        "original": original_content
    }

@app.patch("/api/crashes/{crash_id}")
def update_crash(crash_id: str, update: StatusUpdate):
    """Update crash status."""
    meta_path = os.path.join(CRASHES_DIR, f"meta_{crash_id}.json")
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

@app.get("/api/stats")
def get_stats():
    """Get fuzzer statistics."""
    crashes = list_crashes()["crashes"]

    stats = {
        "total": len(crashes),
        "new": sum(1 for c in crashes if c.get("status") == "new"),
        "verified": sum(1 for c in crashes if c.get("status") == "verified"),
        "ignored": sum(1 for c in crashes if c.get("status") == "ignored"),
        "submitted": sum(1 for c in crashes if c.get("status") == "submitted"),
        "by_severity": {i: sum(1 for c in crashes if c.get("severity") == i) for i in range(1, 6)}
    }
    return stats

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=6767)
