# Blackbox Protocol — Pre-Deployment Review
*Reviewed by Claude Opus 4.6 | 2026-03-22*
*Fixes applied: 2026-03-22*

## Executive Summary

All critical and high-priority issues identified in the initial review have been fixed. The fuzzer is now ready for deployment on Oracle Cloud ARM64, pending manual verification of `firefox_path` against the actual fuzzfetch output structure on the target server.

The original review found four critical bugs that would have silently dropped real crashes and missed entire rendering code paths. These — along with 10 high-priority and 2 medium-priority issues — have been resolved in-tree. Five medium-priority items (M1, M2, M5, M6, M7) are deferred to post-run iteration as they require architectural changes with low risk/reward ratio pre-deployment.

---

## Critical Issues (Must Fix Before Deploying)

### C1. `ignore_keywords` Suppresses Real ASan Crashes — FIXED

- **File:** `modules/crash_handler.py:28-30`
- **Description:** When Firefox exits non-zero, `detect_issue()` checks `ignore_keywords` *first*. If any ignore keyword appears anywhere in stderr, the function immediately returns `(False, None, 0)` — before ASan keywords are ever checked. On Ubuntu 22.04 + Xvfb + Mesa software rendering, nearly every Firefox run emits `GLib-WARNING`, `libGL error`, or `GraphicsCriticalError`. A genuine `ERROR: AddressSanitizer: heap-use-after-free` crash that also contains any of these strings will be **silently dropped**.
- **Impact:** Will discard the majority of real crashes on Linux. This is a data-loss bug.
- **Fix:** Check sanitizer/crash keywords first; only apply ignore filtering to non-sanitizer crashes:

```python
def detect_issue(run_result: dict, config: dict) -> tuple:
    if run_result["timed_out"]:
        return True, "timeout", 1
    if run_result["error"]:
        return True, f"error: {run_result['error']}", 2

    if run_result["exit_code"] != 0:
        output_lower = run_result["output"].lower()

        # 1. Check for high-value sanitizer crashes FIRST
        severity = 1
        asan_keywords = config.get("asan_keywords", DEFAULT_ASAN_KEYWORDS)
        is_sanitizer = False
        for keyword in asan_keywords:
            if keyword.lower() in output_lower:
                severity = 5
                is_sanitizer = True

        # 2. Only filter by ignore_keywords if NOT a sanitizer crash
        if not is_sanitizer:
            for ignore in config.get("ignore_keywords", []):
                if ignore.lower() in output_lower:
                    return False, None, 0

        for keyword in config["crash_keywords"]:
            if keyword.lower() in output_lower:
                if keyword.lower() in ["segfault", "segmentation fault", "crash", "sigsegv"]:
                    severity = max(severity, 4)
                else:
                    severity = max(severity, 2)

        return True, f"non-zero exit ({run_result['exit_code']})", severity

    output_lower = run_result["output"].lower()
    for keyword in config["crash_keywords"]:
        if keyword.lower() in output_lower:
            return True, f"crash keyword: {keyword}", 3
    return False, None, 0
```

---

### C2. `--headless` Negates Xvfb Rendering Coverage — FIXED

- **File:** `modules/browser.py:62`
- **Description:** The `--headless` flag is unconditionally passed to Firefox. When `use_xvfb: true` in config (as it is), this creates a contradiction: Xvfb provides a virtual display for full rendering, but `--headless` tells Firefox to skip the display entirely and use a headless backend. This means WebGL context creation, Canvas 2D GPU paths, WebRender compositor, and display-server interaction code are all bypassed. Many rendering CVEs (WebGPU buffer overflows, WebRender boundary errors, Canvas UAFs) will never trigger.
- **Impact:** Entire rendering attack surface is unreachable. Strategies targeting Canvas/WebGL/WebRender are wasted.
- **Fix:** Remove `--headless` when Xvfb is configured:

```python
cmd = [
    firefox_path,
    "--no-remote",
    "--profile", profile_dir,
    html_path
]
if not display:
    cmd.insert(1, "--headless")
```

---

### C3. Subsystem Coverage Context Is Dead Code — FIXED

- **File:** `worker.py:60`
- **Description:** `context_str = tracker.build_context_prompt()` computes a coverage table showing which subsystems have been tested and their crash ratios — then the variable is **never used**. It is not passed to `generate_test_case()`, not appended to any prompt, not logged. The entire subsystem tracking feedback loop (the reason `SubsystemTracker` exists) is broken. The LLM never sees which subsystems are underexplored.
- **Impact:** Subsystem-aware targeting is completely non-functional. The LLM has no visibility into coverage gaps.
- **Fix:** Pass `context_str` into the generation prompt. In `worker.py`, after line 70:

```python
combined_prompt = strategy_prompt
if context_str:
    combined_prompt = context_str + "\n\n" + combined_prompt
if plateau_prompt:
    combined_prompt = plateau_prompt + "\n\n" + combined_prompt
```

---

### C4. Missing `ASAN_OPTIONS` — Sanitizer Output May Not Reach stderr — FIXED

- **File:** `modules/browser.py:69-71`
- **Description:** No `ASAN_OPTIONS` environment variable is set before launching Firefox. Mozilla's fuzzfetch ASan builds can inherit or embed default ASan options. If `log_path` is set (common in Mozilla CI environments), ASan output goes to a file rather than stderr, meaning `subprocess.PIPE` captures nothing and all sanitizer crashes go undetected. Additionally, without `detect_leaks=0`, LeakSanitizer runs on shutdown and adds 10-30 seconds of noise per test, wasting time and producing false positives.
- **Impact:** Sanitizer crashes may be invisible. LSan noise wastes timeout budget.
- **Fix:** Explicitly set ASAN_OPTIONS in the environment:

```python
env = os.environ.copy()
if display:
    env["DISPLAY"] = display
# Force ASan output to stderr and disable leak checking
env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1:log_path=stderr"
env["UBSAN_OPTIONS"] = "print_stacktrace=1"
env["TSAN_OPTIONS"] = "report_bugs=1"
```

---

## High Priority Issues (Fix Before Week Run)

### H1. Strategy Counter Race Condition — FIXED

- **File:** `modules/generator.py:87-92`
- **Description:** `STRATEGIES` is a module-level mutable dict. `record_result()` performs `STRATEGIES[name]["uses"] += 1` — a non-atomic read-modify-write operation. With `ThreadPoolExecutor` and 2+ workers, concurrent increments can lose updates. The `+=` operator is not atomic even under the GIL (it's `LOAD_ATTR`, `BINARY_ADD`, `STORE_ATTR` — a thread switch between LOAD and STORE loses the increment).
- **Impact:** UCB1 bandit scores become inaccurate. Strategy selection degrades but doesn't crash.
- **Fix:** Add a threading lock around `record_result`, or use `threading.Lock` to guard STRATEGIES access.

### H2. Sanitizer Keywords Missing from `asan_keywords` — FIXED

- **File:** `config.json:42-51`
- **Description:** The `asan_keywords` list (which drives severity=5 detection) contains only AddressSanitizer patterns. TSan, MSan, and UBSan crashes will be detected as generic non-zero exits with severity 1-2, meaning they fall below `min_save_severity: 3` and are silently discarded. See the **Sanitizer Gap** section below for exact keywords.
- **Impact:** Entire classes of bugs (data races, uninitialized memory, undefined behavior) are detected but thrown away.

### H3. Missing Linux False Positive Filters — FIXED

- **File:** `config.json:52-68`
- **Description:** The `ignore_keywords` list is tuned for Windows. Ubuntu 22.04 + Xvfb + Mesa produces many additional noise patterns that will trigger false crash detections on non-zero exits. See **False Positive Risk Assessment** below for exact strings.
- **Impact:** False positive flood wastes Opus API budget on minimizing non-crashes.

### H4. `history_max_turns` Config Is Ignored — FIXED

- **File:** `worker.py:13`
- **Description:** `MAX_HISTORY_TURNS = 6` is hardcoded. `config.json:75` has `"history_max_turns": 6` but it is never read. Changing the config value has no effect.
- **Fix:** `MAX_HISTORY_TURNS = config.get("history_max_turns", 6)` — move to inside `worker_loop()` where `config` is available.

### H5. No Prompt Caching on System Prompt — FIXED

- **File:** `modules/generator.py:106-111`
- **Description:** `system=SYSTEM_PROMPT` is passed as a plain string. Anthropic's prompt caching requires a list of content blocks with `cache_control`. With ~960 calls/day, the ~400-token system prompt is re-processed from scratch every time.
- **Fix:**

```python
response = client.messages.create(
    model=GENERATION_MODEL,
    max_tokens=16384,
    system=[{
        "type": "text",
        "text": SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"}
    }],
    messages=messages
)
```

### H6. Dashboard Port Mismatch — FIXED

- **File:** `config.json:9` vs `dashboard/vite.config.js:7`
- **Description:** Config says `"dashboard_port": 5173` but Vite is configured for port `6868`. `main.py:52` prints the wrong dashboard URL.
- **Fix:** Change `config.json` to `"dashboard_port": 6868`, or make `vite.config.js` read from config.

### H7. `firefox_path` May Be Wrong for fuzzfetch — NOTE ADDED

- **File:** `config.json:4`
- **Description:** Path is `/home/ubuntu/firefox-asan/firefox-asan/firefox` with a doubled `firefox-asan` directory. fuzzfetch typically extracts to `./firefox/firefox` inside the target directory, giving a path like `/home/ubuntu/firefox-asan/firefox/firefox`. The doubled directory name needs verification against actual fuzzfetch output structure.
- **Fix:** After running `fuzzfetch --asan -o /home/ubuntu/firefox-asan`, verify the actual binary path with `find /home/ubuntu/firefox-asan -name firefox -type f`.

### H8. `--disable-gpu` Is Not a Firefox Flag — FIXED

- **File:** `modules/browser.py:65`
- **Description:** `--disable-gpu` is a Chromium/Chrome flag. Firefox silently ignores it. To disable GPU compositing in Firefox, use the environment variable `MOZ_DISABLE_GPU=1` or the preference `layers.acceleration.disabled=true` in the profile.
- **Fix:** Remove `--disable-gpu` from the cmd list. If GPU disabling is needed, add `env["MOZ_DISABLE_GPU"] = "1"`.

### H9. No Linux Startup Script — FIXED

- **File:** `start.bat` (Windows only)
- **Description:** There is no `start.sh` for the Linux deployment. On Oracle Cloud ARM64, you need to start Xvfb, the API server, the dashboard, and the fuzzer. Without a startup script, the deployment requires manual setup and risks forgetting Xvfb.
- **Fix:** Create `start.sh`:

```bash
#!/bin/bash
echo "Starting Xvfb..."
Xvfb :99 -screen 0 1920x1080x24 &
sleep 1

echo "Starting API server..."
python3 api.py &

echo "Starting dashboard..."
cd dashboard && npm run dev &
cd ..

sleep 2
echo "Starting fuzzer..."
python3 main.py
```

### H10. System Prompt Lacks Concrete Vulnerability Examples — FIXED

- **File:** `modules/generator.py:6-27`
- **Description:** The system prompt describes general vulnerability patterns but contains zero concrete code examples. LLM fuzzing research shows that few-shot examples of real bug patterns in the system prompt dramatically improve output quality. Without examples, the LLM generates generic DOM manipulation rather than targeted exploit patterns.
- **Fix:** Add 2-3 anonymized examples of real Firefox bug patterns to `SYSTEM_PROMPT`, e.g.:

```
Example pattern (UAF in DOM):
  let el = document.createElement('div');
  document.body.appendChild(el);
  let range = document.createRange();
  range.selectNode(el);
  el.remove();  // C++ destructor frees layout frame
  range.getBoundingClientRect();  // accesses freed frame
```

---

## Medium Priority Issues (Improve During or After)

### M1. `max_tokens=16384` Is Excessive for Generation — DEFERRED

- **File:** `modules/generator.py:108`
- **Description:** HTML test cases are typically 1-5KB (~500-2000 tokens). `max_tokens=16384` allows the model to generate extremely long, unfocused test cases. Reducing to `8192` or `4096` would encourage more focused output without losing crash-finding ability.

### M2. NoveltyTracker / SubsystemTracker Not Shared Between Workers — DEFERRED

- **File:** `worker.py:25-33`
- **Description:** Each worker creates its own `NoveltyTracker`, `PlateauDetector`, and `SubsystemTracker`. Only `CrashDeduplicator` is shared. This means Worker 1 and Worker 2 can generate identical test cases (both pass their independent novelty checks), and subsystem coverage is tracked per-worker rather than globally.
- **Fix:** Create shared instances in `main.py` and pass them to `worker_loop()`, as is already done for `CrashDeduplicator`.

### M3. API Path Traversal (Local Risk Only) — FIXED

- **File:** `api.py:133, 100, 120`
- **Description:** `crash_id` from the URL is passed directly to `os.path.join(CRASHES_DIR, crash_id)`. A crafted crash_id like `../../etc/passwd` would read files outside the crashes directory. Low risk since this is a local-only dashboard, but worth sanitizing.
- **Fix:** `crash_id = os.path.basename(crash_id)` before path construction.

### M4. No Firefox Version Capture — FIXED

- **Description:** The fuzzer doesn't record which Firefox build/version is being tested. Bugzilla reports require the exact version. Run `firefox --version` at startup and include it in crash metadata.

### M5. NoveltyTracker Refitting Performance — DEFERRED

- **File:** `modules/novelty.py:32-33`
- **Description:** `fit_transform` is called on the entire corpus (up to 500 documents) for every novelty check. With 500 HTML documents of 2-5KB and char n-grams (3,6), this takes 0.5-2 seconds per call. Over a week, this accumulates to hours of wasted compute.
- **Fix:** Use incremental vectorization, or only refit periodically (e.g., every 50 new documents).

### M6. `CrashDeduplicator.is_duplicate()` Scans All Crash Files Under Lock — DEFERRED

- **File:** `modules/crash_handler.py:96-104`
- **Description:** For every new signature, the method reads every `meta.json` in the crashes directory while holding the threading lock. With hundreds of crashes, this blocks other workers during the scan.
- **Fix:** Load all existing signatures from disk once at startup into the `seen` dict, then only check in-memory.

### M7. Plateau Detector Measures Wrong Signal — DEFERRED

- **File:** `worker.py:112`
- **Description:** `plateau_detector.update(True)` is called for all tests that pass the novelty check, regardless of whether they found a crash. The plateau detector is effectively measuring the novelty-skip rate, not crash diversity. It only triggers if >95% of tests are novelty-skipped, which is an extremely high bar.

---

## Missing Attack Surfaces (Bounty Impact)

### 1. WebGPU / WebRender (Estimated: $5,000-$10,000+)

Multiple 2025 CVEs stem from boundary errors in WebGPU buffer processing and WebRender compositor. These are memory corruption bugs in new, rapidly-evolving code with limited existing fuzzing coverage. A new strategy should: create WebGPU adapters and devices, allocate GPU buffers with boundary sizes (e.g., `GPUBufferUsage.STORAGE` at exact page boundaries), trigger compute shader dispatches that read/write near buffer edges, and race device destruction against pending GPU operations. Requires removing `--headless` (see C2) to reach the GPU code paths.

### 2. IonMonkey JIT Bounds Check Elimination (Estimated: $5,000-$10,000)

CVE-2025-4919 (Pwn2Own 2025) was triggered by integer overflow in `ExtractLinearSum` during bounds check merging. The technique involves loops with mixed interpreter/JIT iteration counts where index math approaches `INT32_MAX`. A strategy should: create hot loops with predictable iteration counts to trigger JIT compilation, then use index expressions like `(i + 0x7ffffff0) | 0` that overflow during bounds check optimization, accessing arrays out of bounds after the JIT eliminates the check. The existing `type_confusion` strategy is adjacent but doesn't target this specific pattern.

### 3. IPC Sandbox Escape (Estimated: $8,000-$15,000+)

Mozilla's highest bounty tier rewards content-process sandbox escapes via IPC. The fuzzer currently has no strategy for triggering IPC bugs. A strategy should: use APIs that send attacker-controlled data across process boundaries (e.g., `postMessage` with transferable objects, `BroadcastChannel`, `SharedWorker` communication), trigger rapid creation/destruction of content processes via iframe navigation, and exploit IPDL message ordering assumptions by racing multiple IPC channels.

### 4. SpiderMonkey GC During JIT Compilation (Estimated: $3,000-$8,000)

Race between incremental GC and JIT compilation has been a consistent source of high-severity bugs. The existing `gc_pressure` strategy targets GC+DOM interaction but not GC+JIT specifically. A strategy should: trigger JIT compilation of a function (hot loop), then force incremental GC slices during compilation by interleaving allocation-heavy code with the JIT-compiled function, attempting to move or collect objects that the JIT compiler holds raw pointers to.

### 5. CSS Cascade Layers + Houdini Paint API (Estimated: $1,000-$5,000)

New spec areas with limited fuzzing coverage. Cascade layers (`@layer`) interact with the style system in novel ways, and Houdini paint worklets (`CSS.paintWorklet.addModule`) run custom code during the paint phase. A strategy should: define deeply nested `@layer` rules that conflict, trigger style recalculation during `registerPaint` callbacks, and race paint worklet execution against DOM mutations that invalidate the style tree.

---

## False Positive Risk Assessment — RESOLVED

All 23 Linux/Xvfb/Mesa false positive patterns have been added to `ignore_keywords` in `config.json` (now 38 entries total). This is safe because C1 was fixed first — sanitizer crashes are now checked before ignore filtering, so these patterns cannot suppress real ASan/TSan/MSan/UBSan crashes.

The following patterns were added:

```json
"ExceptionHandler::GenerateDump",
"ATTENTION: default value of option",
"Mesa",
"Fontconfig",
"LIBDBUS",
"[Child",
"GConf",
"NSS",
"ALSA",
"PulseAudio",
"MESA-LOADER",
"dri3",
"X11",
"Gdk",
"Gtk",
"g_object",
"Pango",
"XInput",
"ATTENTION: default value of option mesa",
"libEGL",
"Failed to create GBM device",
"failed to load driver",
"glx",
"EGL_EXT_image_dma_buf_import"
```

> **Status:** All strings added to `config.json`. C1 fix ensures these cannot mask sanitizer crashes.

---

## Sanitizer Gap — RESOLVED

All keywords below have been added to `config.json`. `asan_keywords` now has 25 entries (was 8). `crash_keywords` now has 35 entries (was 26).

### Added to `asan_keywords` in `config.json` (triggers severity=5):

```json
"ThreadSanitizer",
"data race",
"TSAN",
"WARNING: ThreadSanitizer",
"MemorySanitizer",
"use-of-uninitialized-value",
"MSAN",
"WARNING: MemorySanitizer",
"UndefinedBehaviorSanitizer",
"runtime error:",
"UBSAN",
"signed integer overflow",
"null pointer passed as argument",
"misaligned address",
"member access within null pointer",
"index out of bounds",
"shift exponent"
```

### Added to `crash_keywords` in `config.json` (broader detection):

```json
"data race on",
"ThreadSanitizer: data race",
"use of uninitialized value",
"runtime error: signed integer overflow",
"runtime error: null pointer",
"runtime error: misaligned address",
"runtime error: index",
"runtime error: member access",
"runtime error: shift"
```

> **Note:** `runtime error:` is a broad pattern. After adding it, monitor for false positives from benign UBSan warnings in non-security-relevant code.

---

## Cost Optimization Audit

### API Calls Inventory

| Location | Model | Purpose | Tokens (est.) | Frequency |
|---|---|---|---|---|
| `generator.py:106` | Sonnet 4.6 | Test case generation | ~2500 in / ~3000 out | Every test (~960/day) |
| `crash_handler.py:135` | Opus 4.6 | Minimize test case | ~3500 in / ~3000 out | Per crash (~10-20/day) |
| `crash_handler.py:179` | Opus 4.6 | Generate report | ~4000 in / ~1500 out | Per crash (~10-20/day) |

### Issues Found

1. ~~**No prompt caching**~~ (H5): **FIXED.** System prompt now uses `cache_control: {"type": "ephemeral"}`.

2. **Model routing is correct**: Sonnet for generation, Opus for analysis only. No issues here.

3. ~~**History trimming works but config is ignored**~~ (H4): **FIXED.** Now reads `config.get("history_max_turns", 6)` inside `worker_loop()`.

4. **No unbounded token growth**: History is trimmed. `run_output[:3000]` is truncated in crash analysis prompts. `html_content[:2000]` is truncated in report prompts. No runaway growth patterns.

5. **`max_tokens=16384` for generation** (M1): Deferred. Higher than necessary but doesn't increase cost (billed on actual tokens).

### Weekly Cost Estimate (2 workers, 180s delay)

| Item | Calculation | Daily | Weekly |
|---|---|---|---|
| Generation (Sonnet) | 960 calls * ($0.0075 in + $0.045 out) | $50.40 | **$352.80** |
| Minimize (Opus) | ~15 calls * ($0.053 in + $0.225 out) | $4.17 | $29.19 |
| Report (Opus) | ~15 calls * ($0.06 in + $0.113 out) | $2.60 | $18.16 |
| **Total** | | **$57.17** | **~$400** |

> **Note:** This assumes Anthropic direct pricing. If the proxy at `168.110.200.73:5000` has different pricing, actual costs may vary. Approximately 85% of cost is Sonnet output tokens — the only way to significantly reduce cost is to reduce generation frequency (increase `delay_between_tests`) or reduce `max_tokens`.

---

## ARM64 Linux Compatibility Checklist

| Check | File:Line | Status | Notes |
|---|---|---|---|
| `preexec_fn=os.setsid` gated for Linux only | `browser.py:74-76` | PASS | `if system != "Windows": preexec = os.setsid` |
| `file:///` prefix only on Windows | `browser.py:57-58` | PASS | Bare absolute path on Linux, Firefox accepts it |
| `DISPLAY` set from `xvfb_display` config | `browser.py:70-71` | PASS | `env["DISPLAY"] = display` when display is set |
| `use_xvfb` wired to worker | `worker.py:42` | PASS | Display passed to `launch_firefox()` |
| `--headless` vs Xvfb | `browser.py:62` | **FIXED** | `--headless` now only added when `display` is None |
| `--disable-gpu` valid for Firefox | `browser.py:65` | **FIXED** | Removed Chromium flag from cmd |
| `firefox_path` correct for fuzzfetch | `config.json:4` | **UNVERIFIED** | `_firefox_path_note` added; verify on server |
| `ASAN_OPTIONS` set | `browser.py:69` | **FIXED** | ASAN_OPTIONS, UBSAN_OPTIONS, TSAN_OPTIONS now set |
| `kill_stale_processes` uses `pkill` on Linux | `browser.py:32-34` | PASS | Correct: `pkill -9 firefox` |
| Process group kill on timeout | `browser.py:22-23` | PASS | `os.killpg(os.getpgid(pid), signal.SIGKILL)` |
| Temp profile cleanup | `browser.py:46-51` | PASS | `shutil.rmtree` with `ignore_errors=True` |
| `start.bat` has Linux equivalent | `start.sh` | **FIXED** | `start.sh` created with Xvfb + trap cleanup |
| Xvfb startup/management | `start.sh` | **FIXED** | Managed by `start.sh` with PID tracking |
| `ThreadPoolExecutor` on ARM64 | `main.py:87` | PASS | Python threading works on aarch64 |
| `scikit-learn` on ARM64 | `requirements.txt:3` | PASS | scikit-learn has aarch64 wheels |

---

## Verdict

### DEPLOY ✅ (after verifying `firefox_path` on server)

All 4 critical issues, 10 high-priority issues, and 2 medium-priority issues have been fixed. The remaining 5 medium-priority items (M1, M2, M5, M6, M7) are deferred to post-run iteration — they improve performance or design but will not cause failures or waste money.

### Pre-Deploy Checklist

1. ~~Fix ignore_keywords ordering (C1)~~ — DONE
2. ~~Remove `--headless` when Xvfb is active (C2)~~ — DONE
3. ~~Set `ASAN_OPTIONS` (C4)~~ — DONE
4. ~~Wire `context_str` into generation prompt (C3)~~ — DONE
5. ~~Add sanitizer keywords to `asan_keywords` (H2)~~ — DONE (25 keywords)
6. ~~Add Linux false positive filters (H3)~~ — DONE (38 keywords)
7. ~~Add strategy counter lock (H1)~~ — DONE
8. ~~Add prompt caching (H5)~~ — DONE
9. **Verify `firefox_path` (H7)** — Run `find ~/firefox-asan -name firefox -type f` on the server
10. ~~Create `start.sh` (H9)~~ — DONE
11. ~~Add concrete vulnerability examples to system prompt (H10)~~ — DONE
12. ~~Fix dashboard port mismatch (H6)~~ — DONE (6868)
13. ~~Remove `--disable-gpu` Chromium flag (H8)~~ — DONE
14. ~~Sanitize API path traversal (M3)~~ — DONE
15. ~~Capture Firefox version in crash metadata (M4)~~ — DONE

### Deferred to Post-Run

- M1: Reduce `max_tokens` from 16384
- M2: Share NoveltyTracker/SubsystemTracker across workers
- M5: Incremental TF-IDF vectorization
- M6: Preload crash signatures at startup
- M7: Fix plateau detector signal
