#!/usr/bin/env python3
"""Fuzzer monitoring tool — collects metrics, calls Claude for analysis,
applies safe config changes, and sends Telegram notifications."""

import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
CRASHES_DIR = BASE_DIR / "crashes"
CONFIG_PATH = BASE_DIR / "config.json"
GENERATOR_PATH = BASE_DIR / "modules" / "generator.py"


def send_telegram(message: str, parse_mode="Markdown"):
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram not configured — skipping send")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message[:4096],
        "parse_mode": parse_mode,
    }
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"Telegram failed: {e}")


# ── Data collection ──────────────────────────────────────────


def collect_log_tail(n=200):
    try:
        log_path = LOGS_DIR / "fuzzer.log"
        if not log_path.exists():
            return "No logs yet"
        lines = log_path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return "No logs yet"


def collect_crash_summaries():
    summaries = []
    try:
        if not CRASHES_DIR.exists():
            return []
        cutoff = datetime.now() - timedelta(hours=2)
        for meta_path in CRASHES_DIR.rglob("meta.json"):
            mtime = datetime.fromtimestamp(meta_path.stat().st_mtime)
            if mtime < cutoff:
                continue
            try:
                data = json.loads(meta_path.read_text())
                summaries.append({
                    "crash_id": data.get("crash_id", "unknown"),
                    "severity": data.get("severity", "unknown"),
                    "strategy": data.get("strategy_name", "unknown"),
                    "subsystem": data.get("subsystem", "unknown"),
                    "issue_reason": data.get("issue_reason", "unknown"),
                    "status": data.get("status", "unknown"),
                })
            except Exception:
                continue
    except Exception:
        pass
    return summaries


def collect_crash_counts():
    total = 0
    last_2h = 0
    by_severity = {}
    try:
        if not CRASHES_DIR.exists():
            return {"total": 0, "last_2h": 0, "by_severity": {}}
        cutoff = datetime.now() - timedelta(hours=2)
        for meta_path in CRASHES_DIR.rglob("meta.json"):
            try:
                data = json.loads(meta_path.read_text())
                total += 1
                sev = str(data.get("severity", "unknown"))
                by_severity[sev] = by_severity.get(sev, 0) + 1
                mtime = datetime.fromtimestamp(meta_path.stat().st_mtime)
                if mtime >= cutoff:
                    last_2h += 1
            except Exception:
                continue
    except Exception:
        pass
    return {"total": total, "last_2h": last_2h, "by_severity": by_severity}


def collect_strategy_stats():
    stats = {}
    try:
        if not CRASHES_DIR.exists():
            return stats
        for meta_path in CRASHES_DIR.rglob("meta.json"):
            try:
                data = json.loads(meta_path.read_text())
                name = data.get("strategy_name", "unknown")
                stats[name] = stats.get(name, 0) + 1
            except Exception:
                continue
    except Exception:
        pass
    return stats


def collect_subsystem_stats():
    stats = {}
    try:
        if not CRASHES_DIR.exists():
            return stats
        for meta_path in CRASHES_DIR.rglob("meta.json"):
            try:
                data = json.loads(meta_path.read_text())
                name = data.get("subsystem", "unknown")
                stats[name] = stats.get(name, 0) + 1
            except Exception:
                continue
    except Exception:
        pass
    return stats


def compute_timeout_rate(log_tail: str):
    try:
        lines = log_tail.splitlines()
        status_lines = [l for l in lines if "\u2192" in l]
        if not status_lines:
            return 0.0
        timeout_lines = [l for l in status_lines if "timeout" in l.lower()]
        return len(timeout_lines) / len(status_lines)
    except Exception:
        return 0.0


def compute_novelty_skip_rate(log_tail: str):
    try:
        lines = log_tail.splitlines()
        status_lines = [l for l in lines if "\u2192" in l]
        if not status_lines:
            return 0.0
        skipped_lines = [l for l in status_lines if "SKIPPED" in l]
        return len(skipped_lines) / len(status_lines)
    except Exception:
        return 0.0


def collect_config_snapshot():
    try:
        config = json.loads(CONFIG_PATH.read_text())
        config.pop("api_key", None)
        config.pop("base_url", None)
        return json.dumps(config, indent=2)
    except Exception:
        return "{}"


def collect_strategies_section():
    try:
        src = GENERATOR_PATH.read_text()
        match = re.search(r"(STRATEGIES\s*=\s*\{.*?^\})", src, re.DOTALL | re.MULTILINE)
        if match:
            return match.group(1)
        return "Could not extract STRATEGIES"
    except Exception:
        return "Could not read generator.py"


def collect_system_prompt_preview():
    try:
        src = GENERATOR_PATH.read_text()
        match = re.search(r'SYSTEM_PROMPT\s*=\s*"""(.*?)"""', src, re.DOTALL)
        if match:
            return match.group(1)[:300]
        return "Could not extract SYSTEM_PROMPT"
    except Exception:
        return "Could not read generator.py"


# ── Claude analysis ─────────────────────────────────────────


def call_claude(data: dict) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

    user_prompt = f"""BROWSER TESTING TOOL — STATUS REPORT (last 2 hours)

PERFORMANCE METRICS:
- Total findings ever: {data['crash_counts']['total']}
- Findings last 2h: {data['crash_counts']['last_2h']}
- Timeout rate: {data['timeout_rate']:.1%}
- Duplicate skip rate: {data['novelty_skip_rate']:.1%}

FINDINGS BY STRATEGY: {json.dumps(data['strategy_stats'])}
FINDINGS BY TARGET: {json.dumps(data['subsystem_stats'])}
SEVERITY BREAKDOWN: {json.dumps(data['crash_counts']['by_severity'])}

RECENT FINDINGS (last 2h):
{json.dumps(data['crash_summaries'], indent=2)}

RECENT LOGS (last 200 lines):
{data['log_tail']}

CURRENT CONFIG:
{data['config_snapshot']}

CURRENT STRATEGIES:
{data['strategies_section']}

Respond in this EXACT JSON format, no other text:
{{
  "summary": "2-3 sentence plain English summary of tool performance",
  "health": "good|warning|critical",
  "auto_fixes": [
    {{
      "description": "what this fixes and expected impact",
      "confidence": "high",
      "file": "config.json",
      "type": "config_value",
      "key": "timeout_seconds",
      "value": 45
    }}
  ],
  "manual_fixes": [
    {{
      "description": "what this fixes and why it needs human review",
      "file": "modules/generator.py",
      "type": "code_change",
      "instruction": "exact description of what to change"
    }}
  ],
  "red_flags": ["list of urgent issues, empty if none"],
  "telegram_message": "Markdown formatted status message max 600 chars with emojis"
}}

AUTO FIX RULES — only suggest for these types:
- type "config_value": change one key in config.json
- type "add_keyword": append string to a list in config.json

NEVER suggest auto fixes for:
- Any .py file changes
- Removing existing values
- Changing workers count
- Anything requiring code logic"""

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": "claude-opus-4-5",
        "max_tokens": 2048,
        "system": "You are a performance analyst for an automated browser testing tool. Analyze the metrics provided and suggest specific, safe improvements. Be concise. Always reference exact file names and config keys.",
        "messages": [{"role": "user", "content": user_prompt}],
    }

    url = base_url.rstrip("/") + "/v1/messages"
    resp = requests.post(url, headers=headers, json=body, timeout=120)
    resp.raise_for_status()
    resp_json = resp.json()

    # Handle both standard Anthropic and proxy response formats
    if "content" in resp_json and resp_json["content"]:
        content = resp_json["content"][0]["text"]
    elif "choices" in resp_json:
        # OpenAI-compatible proxy format
        content = resp_json["choices"][0]["message"]["content"]
    else:
        raise ValueError(f"Unexpected API response format: {json.dumps(resp_json)[:500]}")

    # Strip markdown fences if Claude wrapped the JSON
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1]
        content = content.rsplit("```", 1)[0]
        content = content.strip()

    return json.loads(content)


# ── Auto-fix execution ──────────────────────────────────────


def apply_auto_fixes(fixes: list) -> list:
    applied = []
    for fix in fixes:
        try:
            config = json.loads(CONFIG_PATH.read_text())
            fix_type = fix.get("type")
            key = fix.get("key")
            value = fix.get("value")

            if fix_type == "config_value":
                config[key] = value
            elif fix_type == "add_keyword":
                if key in config and isinstance(config[key], list):
                    config[key].append(value)
                else:
                    continue
            else:
                continue

            CONFIG_PATH.write_text(json.dumps(config, indent=4) + "\n")

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"{ts} | AUTO-APPLIED | {fix.get('description', '')} | {key}={value}\n"
            auto_fix_log = LOGS_DIR / "auto_fixes.log"
            with open(auto_fix_log, "a") as f:
                f.write(log_line)

            applied.append(fix)
        except Exception as e:
            print(f"Auto-fix failed for {fix}: {e}")
    return applied


# ── Telegram messages ────────────────────────────────────────


def send_notifications(result: dict, applied_fixes: list):
    # Message 1 — always
    send_telegram(result.get("telegram_message", "No message from analysis"))

    # Message 2 — if manual_fixes or red_flags
    manual_fixes = result.get("manual_fixes", [])
    red_flags = result.get("red_flags", [])
    auto_fixes = result.get("auto_fixes", [])

    if manual_fixes or red_flags:
        text = "\u23f3 *Needs your attention:*\n\n"
        if red_flags:
            text += "\U0001f6a8 *Issues:*\n"
            for f in red_flags:
                text += f"\u2022 {f}\n"
            text += "\n"
        if manual_fixes:
            text += "\U0001f527 *Suggested improvements:*\n"
            for i, fix in enumerate(manual_fixes, 1):
                text += f"{i}. `{fix.get('file', '')}` \u2014 {fix.get('description', '')}\n"
            text += "\nTo apply: review and tell Opus to implement"
        if applied_fixes:
            text += "\n\u2705 *Already applied automatically:*\n"
            for fix in applied_fixes:
                text += f"\u2022 {fix.get('description', '')}\n"
        send_telegram(text)

    # Message 3 — critical
    if result.get("health") == "critical":
        text = "\U0001f534 *URGENT: Tool needs attention*\n\n"
        text += "\n".join(red_flags)
        text += "\n\nSSH in: tmux attach -t fuzzer"
        send_telegram(text)


# ── Claude Code auto-apply ──────────────────────────────────


def apply_with_claude_code(manual_fixes: list, suggestions_file: str):
    """Invoke Claude Code non-interactively to apply manual fixes.
    Returns output string on success, None on failure."""
    if not manual_fixes:
        return None

    fix_instructions = "\n".join([
        f"{i+1}. In {fix['file']}: {fix['instruction']}"
        for i, fix in enumerate(manual_fixes)
    ])

    prompt = f"""You are maintaining a Firefox fuzzer codebase.
Apply these specific improvements identified by the performance
monitor. Read each file fully before editing. Make only the
changes listed — do not refactor or change anything else.

Changes to apply:
{fix_instructions}

After applying all changes:
1. Run: python3 -c "from modules import browser, generator, \
   novelty, subsystem_tracker, crash_handler, plateau_detector, \
   storage; print('Imports OK')"
2. If imports fail, revert the breaking change and report why
3. Print a one-line summary of each change made

Context: this is an authorized Mozilla bug bounty research tool
running on a private VPS. Full details in REPORT.md.
"""

    try:
        result = subprocess.run(
            ["claude", "--print", "--dangerously-skip-permissions", prompt],
            cwd="/home/ubuntu/blackbox-protocol",
            capture_output=True,
            text=True,
            timeout=300,
        )

        output = result.stdout + result.stderr

        with open(LOGS_DIR / "claude_code_runs.log", "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"{datetime.now().isoformat()}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"Fixes attempted: {len(manual_fixes)}\n")
            f.write(f"Output:\n{output[:3000]}\n")

        if result.returncode != 0:
            print(f"Claude Code exited with code {result.returncode}")
            return None

        return output if output else None

    except subprocess.TimeoutExpired:
        print("Claude Code timed out after 5 minutes")
        return None
    except FileNotFoundError:
        print("Claude Code not installed — run: npm install -g @anthropic-ai/claude-code")
        return None
    except Exception as e:
        print(f"Claude Code error: {e}")
        return None


def restart_fuzzer():
    """Kill current fuzzer tmux session and restart it."""
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", "fuzzer"],
            capture_output=True, timeout=10,
        )
        time.sleep(3)

        subprocess.run([
            "tmux", "new-session", "-d", "-s", "fuzzer",
            "/home/ubuntu/blackbox-protocol/start.sh",
        ], timeout=10)

        with open(LOGS_DIR / "restarts.log", "a") as f:
            f.write(f"{datetime.now().isoformat()} | Restarted by watch.py\n")

    except Exception as e:
        send_telegram(f"\u26a0\ufe0f *Fuzzer restart failed:* {e}\n\nRestart manually: ./start.sh")


# ── Main ─────────────────────────────────────────────────────


def main():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Watcher starting...")

    # Collect all data
    log_tail = collect_log_tail()
    crash_summaries = collect_crash_summaries()
    crash_counts = collect_crash_counts()
    strategy_stats = collect_strategy_stats()
    subsystem_stats = collect_subsystem_stats()
    timeout_rate = compute_timeout_rate(log_tail)
    novelty_skip_rate = compute_novelty_skip_rate(log_tail)
    config_snapshot = collect_config_snapshot()
    strategies_section = collect_strategies_section()
    system_prompt_preview = collect_system_prompt_preview()

    data = {
        "log_tail": log_tail,
        "crash_summaries": crash_summaries,
        "crash_counts": crash_counts,
        "strategy_stats": strategy_stats,
        "subsystem_stats": subsystem_stats,
        "timeout_rate": timeout_rate,
        "novelty_skip_rate": novelty_skip_rate,
        "config_snapshot": config_snapshot,
        "strategies_section": strategies_section,
        "system_prompt_preview": system_prompt_preview,
    }

    # Call Claude for analysis
    try:
        result = call_claude(data)
    except json.JSONDecodeError as e:
        msg = f"Watcher: Claude returned invalid JSON — {e}"
        print(msg)
        send_telegram(f"\u26a0\ufe0f {msg}")
        return
    except Exception as e:
        msg = f"Watcher: Claude API call failed — {e}"
        print(msg)
        send_telegram(f"\u26a0\ufe0f {msg}")
        return

    # Save full response
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    suggestions_path = LOGS_DIR / f"suggestions_{ts_file}.txt"
    suggestions_path.write_text(json.dumps(result, indent=2))

    # Apply auto-fixes
    applied = apply_auto_fixes(result.get("auto_fixes", []))

    # Log summary
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    health = result.get("health", "unknown")
    n_auto = len(applied)
    n_manual = len(result.get("manual_fixes", []))
    crashes_2h = crash_counts.get("last_2h", 0)
    log_line = f"{ts} | health:{health} | auto:{n_auto} | manual:{n_manual} | crashes_2h:{crashes_2h}\n"
    with open(LOGS_DIR / "watcher.log", "a") as f:
        f.write(log_line)

    # Send Telegram
    send_notifications(result, applied)

    # Auto-apply manual fixes via Claude Code if enabled
    config = json.loads(CONFIG_PATH.read_text())
    claude_code_enabled = config.get("claude_code_auto_apply", False)
    manual_fixes = result.get("manual_fixes", [])

    if claude_code_enabled and manual_fixes:
        send_telegram("\U0001f916 *Claude Code is applying manual fixes...*")

        output = apply_with_claude_code(manual_fixes, str(suggestions_path))

        if output:
            restart_fuzzer()

            send_telegram(
                f"\u2705 *Claude Code finished*\n\n"
                f"Applied {len(manual_fixes)} fix(es).\n"
                f"Fuzzer restarted.\n\n"
                f"Check logs/claude\\_code\\_runs.log for details"
            )
        else:
            send_telegram("\u26a0\ufe0f *Claude Code produced no output \u2014 check logs*")

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Watcher done — health:{health} auto:{n_auto} manual:{n_manual}")


if __name__ == "__main__":
    main()
