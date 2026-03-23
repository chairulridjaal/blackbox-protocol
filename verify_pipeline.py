#!/usr/bin/env python3
"""
verify_pipeline.py — Full end-to-end verification of the fuzzer pipeline.
Tests every stage: generation → extraction → novelty → execution → detection.
"""

import os
import sys
import json
import time
import tempfile
import shutil
from dotenv import load_dotenv

load_dotenv(override=True)

# ── colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
def ok(msg):   print(f"  {GREEN}[PASS]{RESET} {msg}")
def fail(msg): print(f"  {RED}[FAIL]{RESET} {msg}")
def info(msg): print(f"  {CYAN}[INFO]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[WARN]{RESET} {msg}")
def section(title):
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═'*60}{RESET}")

# ── load config ───────────────────────────────────────────────────────────────
with open("config.json") as f:
    config = json.load(f)
config["api_key"] = os.environ.get("ANTHROPIC_API_KEY", config.get("api_key", ""))
config["base_url"] = os.environ.get("ANTHROPIC_BASE_URL", config.get("base_url", ""))

from anthropic import Anthropic
from modules.generator import SYSTEM_PROMPT, STRATEGIES, GENERATION_MODEL, select_strategy
from modules.browser import launch_firefox, create_temp_profile, cleanup_profile
from modules.crash_handler import detect_issue, CrashDeduplicator
from modules.novelty import NoveltyTracker
from modules.subsystem_tracker import SubsystemTracker
from utils.html_utils import extract_html, is_valid_html

client = Anthropic(api_key=config["api_key"], base_url=config["base_url"], timeout=120.0)
display = config.get("xvfb_display", ":99") if config.get("use_xvfb", True) else None
all_pass = True

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1: HTML EXTRACTION LOGIC
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 1: extract_html() edge cases")

test_cases = [
    ("Raw HTML (no fences)", "<!DOCTYPE html><html><body><h1>test</h1></body></html>",
     "<!DOCTYPE html><html><body><h1>test</h1></body></html>"),
    ("Markdown fenced HTML", "```html\n<!DOCTYPE html><html><body>OK</body></html>\n```",
     "<!DOCTYPE html><html><body>OK</body></html>"),
    ("Fenced without lang tag", "```\n<html><body>OK</body></html>\n```",
     "<html><body>OK</body></html>"),
    ("HTML with JS template literals", '<!DOCTYPE html><script>const x = `hello ${name}`;</script>',
     '<!DOCTYPE html><script>const x = `hello ${name}`;</script>'),
    ("HTML with backticks in JS", '<!DOCTYPE html><script>const s = `a` + `b`;</script>',
     '<!DOCTYPE html><script>const s = `a` + `b`;</script>'),
]

for name, input_str, expected in test_cases:
    result = extract_html(input_str)
    if result == expected:
        ok(f"{name}")
    else:
        fail(f"{name}")
        print(f"       Expected: {expected[:80]}...")
        print(f"       Got:      {result[:80]}...")
        all_pass = False

# Test double extraction (worker.py does extract_html twice)
raw_html = "<!DOCTYPE html><html><body><script>const x = `template`;</script></body></html>"
first = extract_html(raw_html)
second = extract_html(first)
if first == second:
    ok("Double extraction is idempotent (safe)")
else:
    fail("Double extraction CHANGES content!")
    print(f"       First:  {first[:80]}...")
    print(f"       Second: {second[:80]}...")
    all_pass = False

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2: GENERATE REAL TEST CASES (2 different strategies)
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 2: Generate test cases via Claude API")

generated = []
strategies_to_test = ["animation_lifecycle", "xslt_xpath"]

for strat_name in strategies_to_test:
    strategy = STRATEGIES[strat_name]
    info(f"Generating: {strat_name}...")

    messages = [
        {"role": "user", "content": f"[TARGET SUBSYSTEM: Web_Animations]\n\n{strategy['prompt']}"}
    ]

    t0 = time.time()
    response = client.messages.create(
        model=GENERATION_MODEL,
        max_tokens=16384,
        system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        messages=messages
    )
    elapsed = time.time() - t0
    raw_content = response.content[0].text
    html_content = extract_html(raw_content)

    info(f"  API response: {elapsed:.1f}s, {len(raw_content)} raw chars")

    # Check 1: Was anything stripped?
    raw_stripped = raw_content.strip()
    if len(html_content) == len(raw_stripped):
        ok(f"  No stripping: raw ({len(raw_content)}) == extracted ({len(html_content)})")
    elif len(html_content) < len(raw_stripped):
        stripped_pct = (1 - len(html_content) / len(raw_stripped)) * 100
        if stripped_pct < 5:
            ok(f"  Minimal stripping: {stripped_pct:.1f}% removed (markdown fences)")
        else:
            warn(f"  Significant stripping: {stripped_pct:.1f}% removed!")
            print(f"       Raw starts with: {raw_content[:100]}")
            print(f"       Extracted starts: {html_content[:100]}")

    # Check 2: Is it valid HTML?
    if is_valid_html(html_content):
        ok(f"  Valid HTML structure detected")
    else:
        fail(f"  NOT valid HTML!")
        print(f"       First 200 chars: {html_content[:200]}")
        all_pass = False

    # Check 3: Has the required comment block?
    has_comment = "Target:" in html_content and "Property:" in html_content
    if has_comment:
        ok(f"  Has Target/Property/Mechanism comment block")
    else:
        warn(f"  Missing structured comment block")

    # Check 4: Has actual JavaScript?
    has_script = "<script" in html_content.lower()
    if has_script:
        ok(f"  Contains <script> tag with JavaScript")
    else:
        warn(f"  No <script> tag found")

    # Check 5: Under line limit?
    line_count = html_content.count('\n') + 1
    if line_count <= 150:
        ok(f"  Line count: {line_count} (under 150 limit)")
    else:
        warn(f"  Line count: {line_count} (exceeds 150 limit)")

    # Check 6: Double extraction safety
    double = extract_html(html_content)
    if double == html_content:
        ok(f"  Double-extraction safe (idempotent)")
    else:
        fail(f"  Double-extraction CHANGES content! Lost {len(html_content) - len(double)} chars")
        all_pass = False

    generated.append({"name": strat_name, "html": html_content, "raw": raw_content})
    print()


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3: NOVELTY CHECK
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 3: Novelty detection")

tracker = NoveltyTracker(threshold=config.get("novelty_threshold", 0.65), max_corpus=500)

if len(generated) >= 2:
    is_novel_1, score_1 = tracker.is_novel(generated[0]["html"])
    info(f"Test 1 ({generated[0]['name']}): novelty={score_1:.3f}, is_novel={is_novel_1}")

    is_novel_2, score_2 = tracker.is_novel(generated[1]["html"])
    info(f"Test 2 ({generated[1]['name']}): novelty={score_2:.3f}, is_novel={is_novel_2}")

    if is_novel_1 and is_novel_2:
        ok("Both test cases are novel (different strategies → different content)")
    elif not is_novel_1:
        fail("First test case not novel?")
        all_pass = False

    # Test duplicate detection
    is_novel_dup, score_dup = tracker.is_novel(generated[0]["html"])
    if not is_novel_dup:
        ok(f"Same HTML correctly detected as duplicate (novelty={score_dup:.3f})")
    else:
        warn(f"Same HTML NOT detected as duplicate (novelty={score_dup:.3f})")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 4: FIREFOX EXECUTION
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 4: Firefox ASan execution")

for gen in generated:
    info(f"Testing: {gen['name']} ({len(gen['html'])} chars)")

    profile_dir = create_temp_profile()
    test_file = os.path.join(profile_dir, "test.html")

    # Write HTML to disk
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(gen["html"])

    # Verify file on disk matches
    with open(test_file, "r", encoding="utf-8") as f:
        disk_content = f.read()

    if disk_content == gen["html"]:
        ok(f"  HTML on disk matches generated content ({len(disk_content)} chars)")
    else:
        fail(f"  HTML on disk DIFFERS! Generated={len(gen['html'])}, Disk={len(disk_content)}")
        all_pass = False

    # Launch Firefox
    t0 = time.time()
    run_result = launch_firefox(
        config["firefox_path"], test_file, profile_dir,
        config["timeout_seconds"], display
    )
    elapsed = time.time() - t0

    info(f"  Exit code: {run_result['exit_code']}, Timed out: {run_result['timed_out']}, Time: {elapsed:.1f}s")

    if run_result["error"]:
        warn(f"  Error: {run_result['error']}")

    # Show crash detection results
    is_issue, issue_reason, severity = detect_issue(run_result, config)
    if is_issue:
        if severity >= 2:
            warn(f"  Issue detected! reason={issue_reason}, severity={severity}")
        else:
            info(f"  Low-severity issue: reason={issue_reason}, severity={severity} (would be skipped)")
    else:
        ok(f"  Clean execution — no crash detected")

    # Show filtered output
    output = run_result["output"].strip()
    if output:
        ignore_kw = [kw.lower() for kw in config.get("ignore_keywords", [])]
        lines = [l for l in output.splitlines()
                 if not any(ig in l.lower() for ig in ignore_kw)]
        if lines:
            info(f"  Non-noise output ({len(lines)} lines):")
            for line in lines[:10]:
                print(f"       {line[:120]}")
        else:
            ok(f"  All output is known noise (filtered by ignore_keywords)")
    else:
        info(f"  No output captured")

    cleanup_profile(profile_dir)
    print()


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 5: CRASH DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 5: Crash deduplicator")

dedup = CrashDeduplicator()
test_output = "ERROR: AddressSanitizer: heap-use-after-free\n#0 0x7f1234 in nsIFrame::GetRect\n#1 0x7f5678 in PresShell::Flush"
is_dup1, sig1 = dedup.is_duplicate(test_output, "asan: heap-use-after-free", config["crashes_dir"])
is_dup2, sig2 = dedup.is_duplicate(test_output, "asan: heap-use-after-free", config["crashes_dir"])

if not is_dup1:
    ok(f"First occurrence: not a dup (sig: {sig1[:8]})")
else:
    warn(f"First occurrence incorrectly flagged as dup")

if is_dup2:
    ok(f"Second occurrence: correctly flagged as dup (sig: {sig2[:8]})")
else:
    fail(f"Second occurrence NOT flagged as dup!")
    all_pass = False

if sig1 == sig2:
    ok(f"Same output → same signature (deterministic)")
else:
    fail(f"Same output → different signatures!")
    all_pass = False


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 6: WORKER DIVERGENCE
# ══════════════════════════════════════════════════════════════════════════════
section("STAGE 6: Worker divergence (4 workers)")

# Reset strategies for this test
from modules import generator
for s in generator.STRATEGIES.values():
    s["uses"] = 0
    s["crashes"] = 0

sub_tracker = SubsystemTracker()
picks = []
for i in range(4):
    name, _ = select_strategy()
    sub_tracker.record_test(sub_tracker.get_underexplored(3)[0])
    picks.append(name)

unique_strategies = len(set(picks))
info(f"4 workers picked: {picks}")
if unique_strategies == 4:
    ok(f"All 4 workers selected DIFFERENT strategies")
else:
    warn(f"Only {unique_strategies}/4 unique strategies")


# ══════════════════════════════════════════════════════════════════════════════
# FINAL VERDICT
# ══════════════════════════════════════════════════════════════════════════════
section("FINAL VERDICT")
if all_pass:
    print(f"  {GREEN}{BOLD}✓ ALL CHECKS PASSED — Pipeline is working correctly{RESET}")
else:
    print(f"  {RED}{BOLD}✗ SOME CHECKS FAILED — See above for details{RESET}")

# Print the actual HTML for manual inspection
section("GENERATED HTML SAMPLES (for manual review)")
for gen in generated:
    print(f"\n{BOLD}--- {gen['name']} ({len(gen['html'])} chars, {gen['html'].count(chr(10))+1} lines) ---{RESET}")
    print(gen["html"][:3000])
    if len(gen["html"]) > 3000:
        print(f"  ... ({len(gen['html']) - 3000} more chars)")
    print()
