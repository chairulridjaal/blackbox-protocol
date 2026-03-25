#!/usr/bin/env python3
"""
Crash Verification Daemon — Blackbox Protocol

Watches crashes/ for new findings, runs automated reproducibility and
environment variation tests, then sends evidence to Claude for expert
analysis and Bugzilla-ready verification reports.

The human is ALWAYS the final decision maker. This tool only investigates
and prepares — it never submits anything, never deletes anything, and
never marks anything as verified without human confirmation.

Architecture:
    1. Watchdog monitors crashes/ for new subdirectories
    2. For each new crash:
       a. Re-run the reproducer 5 times (reproducibility)
       b. Parse all ASan output forensically
       c. Test with JIT disabled (interpreter-only)
       d. Test with GC Zeal mode 2 (aggressive GC on every alloc)
       e. Generate + test simple variants (reduced loops, no timers)
       f. Send all evidence to Claude API for expert analysis
       g. Save verification_report.txt to the crash folder
       h. Update meta.json status to "awaiting_review"
       i. Send Telegram summary to the human

Usage:
    python3 verify.py          # Watch for new crashes continuously
    python3 verify.py --once   # Process existing unverified crashes and exit
"""

import os
import sys
import json
import time
import re
import shutil
import signal
import threading
import logging
import traceback
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from anthropic import Anthropic

from src.modules.browser import (
    launch_firefox,
    create_temp_profile,
    cleanup_profile,
    kill_stale_processes,
)


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_CONCURRENT = 2          # Max simultaneous verifications
REPRO_RUNS = 5              # Number of reproducibility test runs
VERIFY_TIMEOUT = 30         # Timeout per Firefox run (seconds)
SETTLE_DELAY = 10           # Wait for fuzzer to finish writing files
ANALYSIS_MODEL = "claude-opus-4-5"

logger = logging.getLogger("verifier")
_semaphore = threading.Semaphore(MAX_CONCURRENT)
_processing = set()         # Track crash IDs currently being processed
_processing_lock = threading.Lock()


# ─── Logging ──────────────────────────────────────────────────────────────────

def setup_logging():
    """Configure logging to both file and console."""
    os.makedirs("logs", exist_ok=True)

    formatter = logging.Formatter(
        "[%(asctime)s] [VERIFIER] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler("logs/verifier.log", mode="a")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config():
    """Load config.json and .env secrets."""
    load_dotenv(override=True)

    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../config/config.json"
    )
    with open(config_path) as f:
        config = json.load(f)

    config["api_key"] = os.environ.get(
        "ANTHROPIC_API_KEY", config.get("api_key", "")
    )
    config["base_url"] = os.environ.get(
        "ANTHROPIC_BASE_URL", config.get("base_url", "")
    )
    return config


# ─── Telegram ─────────────────────────────────────────────────────────────────

def send_telegram(message, parse_mode="HTML"):
    """Send a Telegram notification. Uses HTML parse mode to avoid
    Markdown conflicts with underscores in crash IDs and strategy names.
    Fails silently with a log warning."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        logger.warning("Telegram credentials not configured — skipping notification")
        return False

    try:
        if len(message) > 4000:
            message = message[:3997] + "..."

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": parse_mode,
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=15)
        return True
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False


# ─── ASan Output Forensics ────────────────────────────────────────────────────

def parse_asan_output(output):
    """Parse ASan / sanitizer output into structured forensic data.

    Returns a dict with error_type, access_type, access_size, address,
    scariness, stack_frames, free_frames, alloc_frames, and is_write.
    Returns None if no sanitizer output detected.
    """
    if not output:
        return None

    result = {
        "error_type": None,
        "access_type": None,
        "access_size": None,
        "address": None,
        "scariness": 0,
        "stack_frames": [],
        "free_frames": [],
        "alloc_frames": [],
        "thread_info": None,
        "is_write": False,
    }

    # ── Error type ────────────────────────────────────────────────────────
    m = re.search(r"ERROR:\s*\w+Sanitizer:\s*(\S+)", output)
    if m:
        result["error_type"] = m.group(1)

    # ── Access type / size ────────────────────────────────────────────────
    m = re.search(r"(READ|WRITE)\s+of\s+size\s+(\d+)", output)
    if m:
        result["access_type"] = m.group(1)
        result["access_size"] = int(m.group(2))
        result["is_write"] = m.group(1) == "WRITE"

    # ── Faulting address ──────────────────────────────────────────────────
    m = re.search(r"on address\s+(0x[0-9a-f]+)", output)
    if m:
        result["address"] = m.group(1)

    # ── ASAN Scariness score ──────────────────────────────────────────────
    m = re.search(r"Scariness:\s*(\d+)", output)
    if m:
        result["scariness"] = int(m.group(1))

    # ── Stack frames (crash, freed-by, allocated-by) ──────────────────────
    section = "crash"
    for line in output.splitlines():
        stripped = line.strip()
        low = stripped.lower()

        if "freed by thread" in low:
            section = "free"
        elif "previously allocated" in low or "allocated by thread" in low:
            section = "alloc"
        elif re.match(r"==\d+==ERROR", stripped):
            section = "crash"

        frame_m = re.match(
            r"#\d+\s+0x[0-9a-f]+\s+in\s+(.+?)(?:\s+\(|$)", stripped
        )
        if not frame_m:
            frame_m = re.match(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", stripped)
        if frame_m:
            frame = frame_m.group(1).strip()
            if section == "free":
                if len(result["free_frames"]) < 10:
                    result["free_frames"].append(frame)
            elif section == "alloc":
                if len(result["alloc_frames"]) < 10:
                    result["alloc_frames"].append(frame)
            else:
                if len(result["stack_frames"]) < 15:
                    result["stack_frames"].append(frame)

    # ── Thread info ───────────────────────────────────────────────────────
    m = re.search(r"[Tt]hread\s+T(\d+)", output)
    if m:
        result["thread_info"] = f"T{m.group(1)}"

    # ── MOZ_CRASH / MOZ_ASSERT (Firefox-specific) ─────────────────────────
    for keyword in [
        "MOZ_CRASH", "MOZ_RELEASE_ASSERT", "MOZ_ASSERT",
        "MOZ_DIAGNOSTIC_ASSERT", "NS_ASSERTION",
    ]:
        if keyword in output and not result["error_type"]:
            result["error_type"] = keyword

    has_data = result["error_type"] or result["stack_frames"]
    return result if has_data else None


# ─── Firefox Test Execution ───────────────────────────────────────────────────

def run_single_test(config, html_path, display=None,
                    extra_env=None, extra_prefs=None, timeout=None):
    """Run a single Firefox test with full ASAN config.

    Creates a temp profile, optionally writes user.js prefs,
    copies the HTML, launches Firefox, and cleans up.
    """
    profile_dir = create_temp_profile()
    try:
        # Write Firefox preferences (JIT disable, etc.)
        if extra_prefs:
            user_js = os.path.join(profile_dir, "user.js")
            with open(user_js, "w") as f:
                for key, value in extra_prefs.items():
                    if isinstance(value, bool):
                        f.write(f'user_pref("{key}", {str(value).lower()});\n')
                    elif isinstance(value, (int, float)):
                        f.write(f'user_pref("{key}", {value});\n')
                    else:
                        f.write(f'user_pref("{key}", "{value}");\n')

        # Copy HTML into profile directory
        test_file = os.path.join(profile_dir, "test_verify.html")
        shutil.copy2(html_path, test_file)

        return launch_firefox(
            config["firefox_path"],
            test_file,
            profile_dir,
            timeout=timeout or VERIFY_TIMEOUT,
            display=display,
            extra_env=extra_env,
        )
    finally:
        cleanup_profile(profile_dir)


# ─── Reproducibility Testing ─────────────────────────────────────────────────

def test_reproducibility(config, html_path, display=None, runs=REPRO_RUNS):
    """Run the reproducer N times and collect structured results."""
    results = []
    for i in range(runs):
        logger.info(f"  Reproducibility run {i + 1}/{runs}...")
        result = run_single_test(config, html_path, display=display)

        crashed = (
            result["exit_code"] != 0
            and not result.get("error")
            and not result["timed_out"]
        )
        asan = parse_asan_output(result.get("output", ""))

        results.append({
            "run": i + 1,
            "exit_code": result["exit_code"],
            "timed_out": result["timed_out"],
            "crashed": crashed,
            "has_asan": asan is not None,
            "asan": asan,
            "output_snippet": (result.get("output", ""))[:2000],
        })
        time.sleep(1)

    crash_count = sum(1 for r in results if r["crashed"])
    asan_count = sum(1 for r in results if r["has_asan"])
    return {
        "runs": results,
        "crash_count": crash_count,
        "asan_count": asan_count,
        "total_runs": runs,
        "crash_rate": f"{crash_count}/{runs}",
        "deterministic": crash_count == runs,
        "classification": (
            "DETERMINISTIC" if crash_count == runs else
            "REPRODUCIBLE" if crash_count >= 3 else
            "FLAKY" if crash_count >= 1 else
            "UNREPRODUCIBLE"
        ),
    }


# ─── Environment Variation Testing ───────────────────────────────────────────

def test_env_variations(config, html_path, display=None):
    """Test with JIT disabled and GC Zeal to characterize the bug class."""
    variations = {}

    # ── 1. JIT disabled (interpreter-only) ────────────────────────────────
    logger.info("  Testing with JIT disabled (interpreter-only)...")
    jit_result = run_single_test(
        config, html_path, display=display,
        extra_prefs={
            "javascript.options.ion": False,
            "javascript.options.baselinejit": False,
            "javascript.options.native_regexp": False,
        },
    )
    jit_crashed = (
        jit_result["exit_code"] != 0
        and not jit_result.get("error")
        and not jit_result["timed_out"]
    )
    variations["jit_disabled"] = {
        "crashed": jit_crashed,
        "exit_code": jit_result["exit_code"],
        "timed_out": jit_result["timed_out"],
        "asan": parse_asan_output(jit_result.get("output", "")),
        "output_snippet": (jit_result.get("output", ""))[:1500],
        "interpretation": (
            "CRASH reproduces WITHOUT JIT → interpreter/DOM/layout bug (not JIT-specific)"
            if jit_crashed else
            "No crash without JIT → likely a JIT compiler bug (mis-compilation, type confusion, range analysis)"
        ),
    }
    time.sleep(1)

    # ── 2. GC Zeal mode 2 (GC on every allocation) ───────────────────────
    logger.info("  Testing with GC Zeal mode (aggressive GC)...")
    gc_result = run_single_test(
        config, html_path, display=display,
        extra_env={"JS_GC_ZEAL": "2,1"},
    )
    gc_crashed = (
        gc_result["exit_code"] != 0
        and not gc_result.get("error")
        and not gc_result["timed_out"]
    )
    variations["gc_zeal"] = {
        "crashed": gc_crashed,
        "exit_code": gc_result["exit_code"],
        "timed_out": gc_result["timed_out"],
        "asan": parse_asan_output(gc_result.get("output", "")),
        "output_snippet": (gc_result.get("output", ""))[:1500],
        "interpretation": (
            "CRASH reproduces with aggressive GC → GC timing is involved (possible rooting hazard / barrier bug)"
            if gc_crashed else
            "No crash with GC Zeal → bug may not be GC-timing-dependent"
        ),
    }

    return variations


# ─── Variant Testing ──────────────────────────────────────────────────────────

def generate_variants(html_content):
    """Generate systematic mutations to isolate the essential crash trigger.

    Returns list of (name, modified_html, description) tuples.
    """
    variants = []

    # ── Variant 1: Reduce loop iterations ─────────────────────────────────
    # Changes loops like `i < 100000` to `i < 100`
    # If crash still happens → JIT warmup is NOT essential
    modified = re.sub(
        r"(\bfor\s*\([^;]*;\s*\w+\s*<\s*)\d{4,}",
        r"\g<1>100",
        html_content,
    )
    if modified != html_content:
        variants.append((
            "reduced_iterations",
            modified,
            "Reduced loop iterations to 100 — tests whether JIT warmup is essential",
        ))

    # ── Variant 2: Remove async timers ────────────────────────────────────
    # Replaces setTimeout/requestAnimationFrame with immediate invocation
    modified = html_content
    modified = re.sub(
        r"setTimeout\s*\(\s*([^,]+),\s*\d+\s*\)",
        r"(\1)()",
        modified,
    )
    modified = re.sub(
        r"requestAnimationFrame\s*\(\s*([^)]+)\s*\)",
        r"(\1)()",
        modified,
    )
    if modified != html_content:
        variants.append((
            "no_async_timers",
            modified,
            "Replaced async timers with immediate execution — tests timing dependency",
        ))

    # ── Variant 3: Remove .remove() / removeChild calls ───────────────────
    # If crash disappears → the removal is essential (UAF pattern)
    modified = re.sub(r"\.remove\s*\(\s*\)", ".style.display='none'", html_content)
    modified = re.sub(
        r"\.removeChild\s*\(([^)]+)\)",
        r".appendChild(\1) /* removeChild disabled */",
        modified,
    )
    if modified != html_content:
        variants.append((
            "no_removal",
            modified,
            "Replaced node removal with hide/re-append — tests whether removal is the essential UAF trigger",
        ))

    return variants


def test_variants(config, html_content, display=None):
    """Generate and test variants, return results."""
    variants = generate_variants(html_content)
    results = {}

    for name, modified_html, description in variants:
        logger.info(f"  Testing variant: {name}...")

        # Write variant to temp file
        profile_dir = create_temp_profile()
        try:
            variant_path = os.path.join(profile_dir, "variant.html")
            with open(variant_path, "w", encoding="utf-8") as f:
                f.write(modified_html)

            result = launch_firefox(
                config["firefox_path"],
                variant_path,
                profile_dir,
                timeout=VERIFY_TIMEOUT,
                display=display,
            )

            crashed = (
                result["exit_code"] != 0
                and not result.get("error")
                and not result["timed_out"]
            )

            results[name] = {
                "description": description,
                "crashed": crashed,
                "exit_code": result["exit_code"],
                "timed_out": result["timed_out"],
                "output_snippet": (result.get("output", ""))[:1000],
            }
        finally:
            cleanup_profile(profile_dir)
        time.sleep(1)

    return results


# ─── Claude Analysis ─────────────────────────────────────────────────────────

VERIFICATION_SYSTEM = """You are a senior vulnerability researcher with deep expertise in Gecko/Firefox internals, ASan crash analysis, and Mozilla Bugzilla submission. You have verified hundreds of crashes from automated fuzzers.

Your role: analyze structured evidence from automated verification and write a thorough, honest verification report for a human security researcher.

Rules:
- Be precise and honest about uncertainty — "likely" and "possibly" are fine
- Distinguish clearly between MEMORY SAFETY bugs (exploitable) and benign assertions/OOM/DoS
- WRITE access violations are almost always more severe than READ
- Assess exploitability based on specific crash characteristics, not guesses
- Reference real CVE patterns when the evidence supports it
- Never inflate severity — false confidence wastes researcher time
- The human reviewer makes ALL final decisions"""


def build_evidence_prompt(meta, minimized_html, report_text,
                          original_output, repro_results,
                          env_results, variant_results, config):
    """Build the comprehensive evidence prompt for Claude analysis."""

    crash_id = meta.get("crash_id", "unknown")
    firefox_path = config.get("firefox_path", "/path/to/firefox")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Reproducibility section ───────────────────────────────────────────
    repro_lines = []
    for run in repro_results.get("runs", []):
        status = "CRASH" if run["crashed"] else ("TIMEOUT" if run["timed_out"] else "OK")
        asan_tag = " [ASan output]" if run["has_asan"] else ""
        repro_lines.append(
            f"  Run {run['run']}: exit={run['exit_code']} → {status}{asan_tag}"
        )

    # Find the best ASan output from any run
    best_asan = None
    best_asan_snippet = ""
    for run in repro_results.get("runs", []):
        if run.get("asan"):
            best_asan = run["asan"]
            best_asan_snippet = run.get("output_snippet", "")
            break

    # ── ASan forensics section ────────────────────────────────────────────
    asan_section = "No ASan output captured in any verification run."
    if best_asan:
        frames_str = "\n".join(
            f"    #{i} {f}" for i, f in enumerate(best_asan.get("stack_frames", [])[:10])
        )
        free_str = ""
        if best_asan.get("free_frames"):
            free_str = "\nFreed by:\n" + "\n".join(
                f"    #{i} {f}" for i, f in enumerate(best_asan["free_frames"][:5])
            )
        alloc_str = ""
        if best_asan.get("alloc_frames"):
            alloc_str = "\nAllocated by:\n" + "\n".join(
                f"    #{i} {f}" for i, f in enumerate(best_asan["alloc_frames"][:5])
            )

        asan_section = f"""Error type: {best_asan.get('error_type', 'unknown')}
Access: {best_asan.get('access_type', 'unknown')} of size {best_asan.get('access_size', '?')}
Address: {best_asan.get('address', 'unknown')}
Scariness: {best_asan.get('scariness', 0)}/100
Thread: {best_asan.get('thread_info', 'unknown')}
Is write: {best_asan.get('is_write', False)}

Stack trace:
{frames_str}{free_str}{alloc_str}"""

    # ── Environment variation section ─────────────────────────────────────
    env_lines = []
    for name, data in env_results.items():
        status = "CRASHED" if data["crashed"] else ("TIMEOUT" if data["timed_out"] else "NO CRASH")
        env_lines.append(f"  {name}: {status} (exit={data['exit_code']})")
        env_lines.append(f"    → {data['interpretation']}")
        if data.get("asan"):
            env_lines.append(f"    → ASan: {data['asan'].get('error_type', 'none')}")

    # ── Variant test section ──────────────────────────────────────────────
    variant_lines = []
    for name, data in variant_results.items():
        status = "CRASHED" if data["crashed"] else ("TIMEOUT" if data["timed_out"] else "NO CRASH")
        variant_lines.append(f"  {name}: {status}")
        variant_lines.append(f"    {data['description']}")

    # ── Build the full prompt ─────────────────────────────────────────────
    prompt = f"""Analyze this crash verification evidence and write a complete verification report.

━━━━ CRASH METADATA ━━━━
Crash ID: {crash_id}
Severity (fuzzer-assigned): {meta.get('severity', '?')}/5
Strategy: {meta.get('strategy_name', 'unknown')}
Subsystem: {meta.get('subsystem', 'unknown')}
Issue reason: {meta.get('issue_reason', 'unknown')}
Firefox version: {meta.get('firefox_version', 'unknown')}
Signature: {meta.get('signature', 'unknown')}

━━━━ MINIMIZED REPRODUCER ━━━━
```html
{minimized_html[:8000]}
```

━━━━ FUZZER'S INITIAL REPORT ━━━━
{report_text[:3000]}

━━━━ RAW ASAN OUTPUT (from initial discovery) ━━━━
{original_output[:4000]}

━━━━ REPRODUCIBILITY TESTING ({repro_results.get('crash_rate', '?')}) ━━━━
Classification: {repro_results.get('classification', 'unknown')}
Deterministic: {repro_results.get('deterministic', False)}

{chr(10).join(repro_lines)}

━━━━ ASAN FORENSICS ━━━━
{asan_section}

━━━━ ENVIRONMENT VARIATIONS ━━━━
{chr(10).join(env_lines) if env_lines else 'No environment variation tests completed.'}

━━━━ VARIANT TESTS ━━━━
{chr(10).join(variant_lines) if variant_lines else 'No variant tests completed.'}

━━━━ YOUR ANALYSIS TASKS ━━━━

1. CLASSIFY THE BUG
   - Error type: UAF, heap-overflow, type-confusion, stack-overflow, null-deref, assertion, OOM, etc.
   - Memory safety bug or logic bug?
   - Which Firefox component? (DOM, Layout, SpiderMonkey JIT, Networking, XSLT, WebAssembly, etc.)

2. ASSESS EXPLOITABILITY (using this taxonomy)
   - EXPLOITABLE: Write-what-where, UAF with controlled replacement, type confusion with controlled dispatch
   - PROBABLY_EXPLOITABLE: Heap write overflow, stack overflow, controlled read primitive
   - PROBABLY_NOT_EXPLOITABLE: Read-only OOB, uncontrolled crash address, null deref at offset 0
   - NOT_EXPLOITABLE: Benign assertion, OOM abort, debug-only check, resource exhaustion

3. COMPARE WITH KNOWN CVE PATTERNS
   Does this resemble any known Firefox CVE? Consider:
   - CVE-2024-9680 (Animation timeline UAF — CVSS 9.8)
   - CVE-2024-29943 (JIT range analysis bypass — $100K Pwn2Own)
   - CVE-2025-1009/3028 (XSLT UAF — Project Zero)
   - CVE-2024-8381 (with-statement type confusion)
   - CVE-2024-8385 (WASM type boundary confusion)
   - CVE-2024-7528 (IndexedDB + GC UAF)
   - CVE-2025-1930 (AudioIPC UAF)

4. DETERMINE VERDICT
   - CONFIRMED: Reproduces reliably (≥3/5), clear memory safety impact
   - LIKELY: Reproduces somewhat (2/5), appears security-relevant
   - FLAKY: Reproduces rarely (1/5), needs more investigation
   - FALSE_POSITIVE: Not a real security bug (assertion, OOM, benign abort, test artifact)
   - UNREPRODUCIBLE: Did not reproduce in any verification run

5. WRITE THE REPORT
   Output the report below. This will be saved as verification_report.txt.
   Start with ---BEGIN REPORT--- and end with ---END REPORT---.

---BEGIN REPORT---
# Verification Report — {crash_id}
Generated: {timestamp}
Verified by: Blackbox Protocol Automated Verifier

## Verdict
[CONFIRMED / LIKELY / FLAKY / FALSE_POSITIVE / UNREPRODUCIBLE]
Confidence: [High / Medium / Low]

## Bug Classification
Type: [use-after-free / heap-buffer-overflow / type-confusion / null-deref / assertion / etc.]
Component: [DOM / Layout / SpiderMonkey / XSLT / WebAssembly / Networking / etc.]
Memory safety: [Yes / No]
Reachable from web content: [Yes / No / Unknown]

## Reproducibility
Rate: {repro_results.get('crash_rate', '?')}
Classification: {repro_results.get('classification', 'unknown')}
[Summary of each run's result]

## ASan Forensics
[Structured ASan data: error type, READ/WRITE, address, scariness, top frames]
[For UAF: freed-by and allocated-by traces]

## Environment Variation Analysis
JIT disabled: [crashed / did not crash] — [what this tells us]
GC Zeal: [crashed / did not crash] — [what this tells us]

## Variant Analysis
[Results from each variant and what they reveal about the essential trigger]

## Exploitability Assessment
Rating: [EXPLOITABLE / PROBABLY_EXPLOITABLE / PROBABLY_NOT_EXPLOITABLE / NOT_EXPLOITABLE]
[Detailed justification based on:
 - Is this a WRITE violation?
 - Can attacker control data at the crash address?
 - Is heap grooming feasible (jemalloc bucket prediction)?
 - How many steps from this primitive to code execution?]

## Root Cause Hypothesis
[Your best theory of what's happening at the C++ level.
 Reference specific Gecko classes/methods if the stack trace supports it.
 Explain the invariant violation and the window of vulnerability.]

## Known CVE Comparison
[Whether this matches known CVE patterns and why/why not]

## Recommended Actions for Human Reviewer
1. [Specific action — e.g., "Verify on latest Firefox Nightly"]
2. [Specific action — e.g., "Record with rr for root cause analysis"]
3. [Specific action — e.g., "Check Bugzilla for [function_name]"]
4. [Specific action — e.g., "Test with GDB to inspect register state at crash"]
...

## rr Recording Commands
To do deep root-cause analysis with reverse debugging:
```
rr record {firefox_path} --no-remote --headless --profile /tmp/rr_profile --screenshot /dev/null path/to/minimized.html
rr replay
# At the crash point:
(rr) bt                           # Full backtrace
(rr) info registers               # Register state at crash
(rr) watch -l *<corrupted_addr>   # Watchpoint on corrupted memory
(rr) reverse-continue             # Find the instruction that corrupted it
(rr) bt                           # Backtrace of the corruptor
```

## Bugzilla Search URLs
Search for similar known issues:
[Generate 2-3 Bugzilla search URLs based on the top stack frame function names]

## Raw Evidence
[Include the most significant ASan output snippet and any noteworthy variant results]
---END REPORT---"""

    return prompt


def analyze_with_claude(client, meta, minimized_html, report_text,
                        original_output, repro_results,
                        env_results, variant_results, config):
    """Send all evidence to Claude for expert analysis. Returns report text."""
    prompt = build_evidence_prompt(
        meta, minimized_html, report_text, original_output,
        repro_results, env_results, variant_results, config,
    )

    logger.info("  Sending evidence to Claude for analysis...")
    try:
        response = client.messages.create(
            model=ANALYSIS_MODEL,
            max_tokens=8192,
            system=VERIFICATION_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
    except Exception as e:
        logger.error(f"  Claude API call failed: {e}")
        # Retry once
        try:
            time.sleep(5)
            response = client.messages.create(
                model=ANALYSIS_MODEL,
                max_tokens=8192,
                system=VERIFICATION_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as e2:
            logger.error(f"  Claude API retry failed: {e2}")
            return None


def extract_report(claude_output):
    """Extract the verification report from Claude's output."""
    if not claude_output:
        return None

    # Look for ---BEGIN REPORT--- ... ---END REPORT---
    m = re.search(
        r"---BEGIN REPORT---\s*\n(.*?)---END REPORT---",
        claude_output,
        re.DOTALL,
    )
    if m:
        return m.group(1).strip()

    # Fallback: if the markers are missing, return everything
    # starting from the first "# Verification Report"
    m = re.search(r"(# Verification Report.*)", claude_output, re.DOTALL)
    if m:
        return m.group(1).strip()

    # Last resort: return the full output
    return claude_output.strip()


def extract_verdict_line(report_text):
    """Extract verdict and confidence from the report."""
    verdict = "UNKNOWN"
    confidence = "Unknown"

    m = re.search(
        r"##\s*Verdict\s*\n+\s*(?:\[|\*{1,2})?\s*(CONFIRMED|LIKELY|FLAKY|FALSE_POSITIVE|UNREPRODUCIBLE)",
        report_text,
        re.IGNORECASE,
    )
    if m:
        verdict = m.group(1).upper()

    m = re.search(r"Confidence:\s*(?:\[|\*{1,2})?\s*(High|Medium|Low)", report_text, re.IGNORECASE)
    if m:
        confidence = m.group(1).capitalize()

    return verdict, confidence


def extract_exploitability(report_text):
    """Extract exploitability rating from the report."""
    m = re.search(
        r"Rating:\s*(?:\[|\*{1,2})?\s*(EXPLOITABLE|PROBABLY_EXPLOITABLE|PROBABLY_NOT_EXPLOITABLE|NOT_EXPLOITABLE)",
        report_text,
        re.IGNORECASE,
    )
    return m.group(1).upper() if m else "UNKNOWN"


# ─── Main Processing Pipeline ────────────────────────────────────────────────

def process_crash(crash_dir, config, client):
    """Full verification pipeline for a single crash.

    1. Read crash artifacts
    2. Reproducibility testing (5 runs)
    3. Environment variations (JIT off, GC Zeal)
    4. Variant testing
    5. Claude analysis
    6. Save report + update meta
    7. Telegram notification
    """
    crash_id = os.path.basename(crash_dir)

    # ── Guard: check if already being processed ───────────────────────────
    with _processing_lock:
        if crash_id in _processing:
            logger.info(f"Skipped {crash_id} — already being processed")
            return
        _processing.add(crash_id)

    with _semaphore:
        try:
            _process_crash_inner(crash_dir, crash_id, config, client)
        except Exception as e:
            logger.error(f"Error processing {crash_id}: {e}")
            traceback.print_exc()
        finally:
            with _processing_lock:
                _processing.discard(crash_id)


def _process_crash_inner(crash_dir, crash_id, config, client):
    """Inner processing logic (called under semaphore)."""

    # ── 1. Wait for files to finish writing ───────────────────────────────
    time.sleep(SETTLE_DELAY)

    meta_path = os.path.join(crash_dir, "meta.json")
    if not os.path.exists(meta_path):
        # Retry once after another delay
        time.sleep(SETTLE_DELAY)
        if not os.path.exists(meta_path):
            logger.warning(f"Skipped {crash_id} — meta.json not found")
            return

    # ── 2. Read crash artifacts ───────────────────────────────────────────
    with open(meta_path) as f:
        meta = json.load(f)

    if meta.get("status") != "new":
        logger.info(f"Skipped {crash_id} — status is '{meta.get('status')}', not 'new'")
        return

    # Check if already verified
    report_path = os.path.join(crash_dir, "verification_report.txt")
    if os.path.exists(report_path):
        logger.info(f"Skipped {crash_id} — verification_report.txt already exists")
        return

    logger.info(f"Processing crash: {crash_id} | severity:{meta.get('severity')} | strategy:{meta.get('strategy_name')}")

    # Read available files
    minimized_path = os.path.join(crash_dir, "minimized.html")
    original_path = os.path.join(crash_dir, "original.html")
    report_txt_path = os.path.join(crash_dir, "report.txt")
    output_path = os.path.join(crash_dir, "output.txt")

    # Prefer minimized, fall back to original
    html_path = minimized_path if os.path.exists(minimized_path) else original_path
    if not os.path.exists(html_path):
        logger.warning(f"Skipped {crash_id} — no HTML reproducer found")
        return

    with open(html_path, encoding="utf-8") as f:
        minimized_html = f.read()

    report_text = ""
    if os.path.exists(report_txt_path):
        with open(report_txt_path, encoding="utf-8") as f:
            report_text = f.read()

    original_output = ""
    if os.path.exists(output_path):
        with open(output_path, encoding="utf-8") as f:
            original_output = f.read()
    else:
        original_output = meta.get("output_snippet", "")

    display = config.get("xvfb_display", ":99") if config.get("use_xvfb") else None

    # ── 3. Reproducibility testing ────────────────────────────────────────
    logger.info(f"  Running {REPRO_RUNS} reproducibility tests...")
    repro_results = test_reproducibility(config, html_path, display=display)
    logger.info(
        f"  Reproducibility: {repro_results['crash_rate']} "
        f"({repro_results['classification']})"
    )

    # ── 4. Environment variations ─────────────────────────────────────────
    logger.info("  Running environment variation tests...")
    env_results = test_env_variations(config, html_path, display=display)
    for name, data in env_results.items():
        status = "CRASHED" if data["crashed"] else "no crash"
        logger.info(f"  {name}: {status}")

    # ── 5. Variant testing ────────────────────────────────────────────────
    logger.info("  Running variant tests...")
    variant_results = test_variants(config, minimized_html, display=display)
    for name, data in variant_results.items():
        status = "CRASHED" if data["crashed"] else "no crash"
        logger.info(f"  variant:{name} → {status}")

    # ── 6. Claude analysis ────────────────────────────────────────────────
    claude_output = analyze_with_claude(
        client, meta, minimized_html, report_text, original_output,
        repro_results, env_results, variant_results, config,
    )

    if not claude_output:
        logger.error(f"  Claude analysis failed for {crash_id} — skipping report generation")
        return

    report_content = extract_report(claude_output)
    verdict, confidence = extract_verdict_line(report_content)
    exploitability = extract_exploitability(report_content)

    logger.info(f"  Verdict: {verdict} | Confidence: {confidence} | Exploitability: {exploitability}")

    # ── 7. Save verification report ───────────────────────────────────────
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    logger.info(f"  Saved: {report_path}")

    # ── 8. Update meta.json ───────────────────────────────────────────────
    meta["status"] = "awaiting_review"
    meta["verified_at"] = datetime.now().isoformat()
    meta["verdict"] = verdict
    meta["confidence"] = confidence
    meta["exploitability"] = exploitability
    meta["repro_rate"] = repro_results["crash_rate"]
    meta["repro_classification"] = repro_results["classification"]
    meta["jit_disabled_crashes"] = env_results.get("jit_disabled", {}).get("crashed", False)
    meta["gc_zeal_crashes"] = env_results.get("gc_zeal", {}).get("crashed", False)

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"  Updated meta.json → status: awaiting_review")

    # ── 9. Telegram notification ──────────────────────────────────────────
    _send_crash_notification(crash_id, meta, verdict, confidence,
                             exploitability, repro_results)

    logger.info(f"  Verification complete: {crash_id}")


def _send_crash_notification(crash_id, meta, verdict, confidence,
                             exploitability, repro_results):
    """Send Telegram notification about verified crash."""

    severity = meta.get("severity", "?")
    strategy = meta.get("strategy_name", "unknown")
    subsystem = meta.get("subsystem", "unknown")
    crash_rate = repro_results.get("crash_rate", "?")

    # ── Primary notification ──────────────────────────────────────────────
    msg = (
        "🔬 <b>Crash Verified — Awaiting Your Review</b>\n"
        "\n"
        f"<b>ID:</b> <code>{crash_id}</code>\n"
        f"<b>Severity:</b> {severity}/5\n"
        f"<b>Strategy:</b> {strategy}\n"
        f"<b>Subsystem:</b> {subsystem}\n"
        "\n"
        f"<b>Verdict:</b> {verdict}\n"
        f"<b>Confidence:</b> {confidence}\n"
        f"<b>Exploitability:</b> {exploitability}\n"
        f"<b>Crash rate:</b> {crash_rate}\n"
        "\n"
        "<b>Next steps:</b>\n"
        f"1. Review: <code>crashes/{crash_id}/verification_report.txt</code>\n"
        f"2. Review: <code>crashes/{crash_id}/minimized.html</code>\n"
        "3. Test yourself on latest Firefox Nightly\n"
        "4. If confident → mark as verified in dashboard\n"
        "5. Write your own analysis before submitting to Mozilla\n"
        "\n"
        "⚠️ You are the final decision maker. Never submit without your own independent verification."
    )

    send_telegram(msg)

    # ── High-confidence alert (second message) ────────────────────────────
    if verdict in ("CONFIRMED", "LIKELY") and confidence == "High":
        alert = (
            f"🎯 <b>High-Confidence Finding — </b><code>{crash_id}</code>\n"
            "\n"
            "This crash reproduced reliably and may be a genuine security vulnerability.\n"
            "\n"
            "<b>Suggested deep-dive steps:</b>\n"
            "\n"
            "1. Record with rr for reverse debugging:\n"
            "   <code>rr record firefox --no-remote --headless --screenshot /dev/null minimized.html</code>\n"
            "\n"
            "2. Test on latest Firefox Nightly:\n"
            "   https://www.mozilla.org/firefox/nightly/\n"
            "   If fixed → may already be patched\n"
            "\n"
            "3. Test on latest Firefox ESR:\n"
            "   Different fix schedule — may still be affected\n"
            "\n"
            "4. Search Bugzilla manually:\n"
            "   https://bugzilla.mozilla.org/query.cgi\n"
            "   Search for the component and bug class\n"
            "\n"
            "5. Only submit after YOUR independent verification.\n"
            "   Mozilla bug bounty: https://bugzilla.mozilla.org/form.sec.bounty"
        )

        send_telegram(alert)


# ─── Watchdog Handler ─────────────────────────────────────────────────────────

class CrashFolderHandler(FileSystemEventHandler):
    """Watches crashes/ for new subdirectories."""

    def __init__(self, config, client):
        super().__init__()
        self.config = config
        self.client = client

    def on_created(self, event):
        if not event.is_directory:
            return
        crash_dir = event.src_path
        crash_id = os.path.basename(crash_dir)

        # Ignore hidden/temp directories
        if crash_id.startswith(".") or crash_id.startswith("_"):
            return

        logger.info(f"New crash folder detected: {crash_id}")
        threading.Thread(
            target=process_crash,
            args=(crash_dir, self.config, self.client),
            daemon=True,
        ).start()


# ─── Startup Scan ─────────────────────────────────────────────────────────────

def scan_existing_crashes(crashes_dir, config, client):
    """Process any existing crashes with status 'new' that don't have
    verification reports yet (catch-up for crashes that arrived while
    the verifier was offline).
    """
    if not os.path.isdir(crashes_dir):
        return

    pending = []
    for entry in sorted(os.listdir(crashes_dir)):
        crash_dir = os.path.join(crashes_dir, entry)
        if not os.path.isdir(crash_dir):
            continue
        meta_path = os.path.join(crash_dir, "meta.json")
        report_path = os.path.join(crash_dir, "verification_report.txt")

        if not os.path.exists(meta_path):
            continue
        if os.path.exists(report_path):
            continue

        try:
            with open(meta_path) as f:
                meta = json.load(f)
            if meta.get("status") == "new":
                pending.append(crash_dir)
        except (json.JSONDecodeError, OSError):
            continue

    if pending:
        logger.info(f"Found {len(pending)} unverified crash(es) from previous session")
        for crash_dir in pending:
            threading.Thread(
                target=process_crash,
                args=(crash_dir, config, client),
                daemon=True,
            ).start()
            # Stagger startup to avoid overwhelming the API
            time.sleep(2)
    else:
        logger.info("No unverified crashes found from previous sessions")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    setup_logging()

    logger.info("=" * 60)
    logger.info("BLACKBOX PROTOCOL — Crash Verification Daemon")
    logger.info("=" * 60)
    logger.info("Human review required before any submission")
    logger.info("")

    config = load_config()
    crashes_dir = os.path.abspath(config.get("crashes_dir", "crashes"))
    os.makedirs(crashes_dir, exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    client = Anthropic(
        api_key=config["api_key"],
        base_url=config["base_url"],
        timeout=600.0,
        max_retries=2,
    )

    logger.info(f"Firefox: {config.get('firefox_path', 'NOT SET')}")
    logger.info(f"Crashes dir: {crashes_dir}")
    logger.info(f"Max concurrent verifications: {MAX_CONCURRENT}")
    logger.info(f"Reproducibility runs: {REPRO_RUNS}")
    logger.info(f"Timeout per run: {VERIFY_TIMEOUT}s")
    logger.info(f"Analysis model: {ANALYSIS_MODEL}")

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if tg_token and tg_chat_id:
        logger.info("Telegram notifications: ENABLED")
    else:
        logger.info("Telegram notifications: DISABLED (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)")

    logger.info("")

    # ── Process existing unverified crashes ────────────────────────────────
    scan_existing_crashes(crashes_dir, config, client)

    # ── Check for --once mode ─────────────────────────────────────────────
    if "--once" in sys.argv:
        logger.info("Running in --once mode — waiting for existing verifications to complete...")
        # Wait for all threads to finish
        time.sleep(5)  # Give threads time to start
        while True:
            with _processing_lock:
                if not _processing:
                    break
            time.sleep(2)
        logger.info("All verifications complete. Exiting.")
        return

    # ── Start watchdog ────────────────────────────────────────────────────
    handler = CrashFolderHandler(config, client)
    observer = Observer()
    observer.schedule(handler, crashes_dir, recursive=False)
    observer.start()
    logger.info(f"Watching {crashes_dir}/ for new crashes...")
    logger.info("Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down verifier...")
        observer.stop()
        observer.join()
        logger.info("Verifier stopped.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nVerifier stopped by user.")
