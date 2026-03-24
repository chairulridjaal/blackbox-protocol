# Blackbox Protocol

AI-powered Firefox browser fuzzer that uses Claude to generate surgical, CVE-quality test cases targeting memory corruption vulnerabilities. The fuzzer combines multi-armed bandit strategy selection, semantic novelty detection, exploitability-aware crash triage, and automated Bugzilla-ready report generation into a modular, multi-worker framework built for Mozilla's bug bounty program.

Blackbox Protocol is the **execution layer** of a two-part pipeline. It pairs with [Redbox Protocol](#redbox-protocol-integration), a research agent that reads Firefox C++ source code, identifies vulnerability patterns, and produces targeted **attack briefs** that give Blackbox workers precise, hypothesis-driven targets.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Redbox Protocol Integration](#redbox-protocol-integration)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Dashboard](#dashboard)
- [API Endpoints](#api-endpoints)
- [How It Works](#how-it-works)
- [Fuzzing Strategies](#fuzzing-strategies)
- [Crash Output](#crash-output)
- [Project Structure](#project-structure)
- [Monitoring & Watcher](#monitoring--watcher)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Redbox-Guided Targeting** -- Consumes attack briefs from Redbox Protocol: Claude has read the actual Firefox C++ source and identified specific vulnerable classes, methods, and trigger sequences. Workers prioritize these briefs, then fall back to general strategy fuzzing
- **Red-Team LLM Generation** -- Claude operates as an elite security researcher persona, generating surgical HTML/JS test cases modeled on real CVE patterns (CVE-2024-9680, CVE-2024-29943, CVE-2025-1009, etc.)
- **Multi-Worker Concurrency** -- 2 parallel fuzzing workers with shared state (crash deduplication, novelty corpus, subsystem coverage) and diversified initial prompts to avoid correlated exploration
- **UCB1 Strategy Selection** -- Multi-armed bandit algorithm with atomic strategy claiming under lock, balancing exploration vs. exploitation across 11 attack strategies
- **Semantic Novelty Detection** -- TF-IDF cosine similarity (character 3-6 n-grams) with shared corpus across all workers filters duplicate test cases before execution
- **Plateau Detection** -- Automatically detects stalled novelty rates and injects diversity prompts with subsystem rotation
- **Subsystem Coverage Tracking** -- Monitors 18 Firefox subsystems and steers generation toward underexplored attack surfaces
- **Exploitability-Aware Severity** -- Parses ASAN Scariness scores, detects write-class bugs, UAFs, type confusion, and Mozilla assertion failures to auto-rate crash exploitability (1-5)
- **Hardened ASAN Configuration** -- Tuned sanitizer settings: 64MB quarantine, 512-byte redzones, deterministic fill bytes, stack UAF detection, container overflow checks
- **Firefox Debug Signals** -- `XPCOM_DEBUG_BREAK=stack-and-abort` makes `NS_ASSERTION` fatal; captures `MOZ_CRASH`, `MOZ_RELEASE_ASSERT`, `MOZ_DIAGNOSTIC_ASSERT`
- **Forced Render-and-Exit** -- `--screenshot /dev/null` forces Firefox to render the page and exit (~8s) instead of hanging indefinitely
- **Automated Crash Minimization** -- Claude (Opus) reduces crashing test cases to minimal reproducers
- **Bug Report Generation** -- Produces Bugzilla-ready reports with root cause analysis, security impact, and affected component
- **Crash Deduplication** -- MD5-based stack trace normalization with thread-safe in-memory cache and filesystem cross-check
- **Severity Filtering** -- Configurable minimum severity threshold (default: 2) skips low-value findings
- **Prompt Caching** -- System prompt uses Anthropic `cache_control: ephemeral` to reduce token costs across repeated generations
- **Web Dashboard** -- React-based UI with filtering, search, sorting, bulk actions, and real-time crash triage
- **REST API** -- FastAPI backend for crash management, bulk operations, and statistics
- **Automated Monitoring** -- `watch.py` runs on cron, analyzes performance via Claude, applies safe config fixes, and sends Telegram status updates
- **Claude Code Auto-Apply** -- Optionally invokes Claude Code to apply suggested code changes and restarts the fuzzer automatically

## Architecture

```
╔══════════════════════════════════════════════════════════════╗
║                    REDBOX PROTOCOL                           ║
║  (reads Firefox C++ source → generates attack briefs)        ║
╚══════════════════════════════╦═══════════════════════════════╝
                               ║  briefs/*.json
                               ▼
╔══════════════════════════════════════════════════════════════╗
║                    BLACKBOX PROTOCOL                         ║
║                                                              ║
║  ┌──────────────────────────────────────────────────────┐   ║
║  │                      main.py                          │   ║
║  │               (orchestrator + shared state)           │   ║
║  └───────────────┬──────────────────────┬───────────────┘   ║
║                  │                      │                    ║
║          ┌───────┴───────┐    ┌─────────┴──────┐           ║
║          │   Worker 1    │    │   Worker 2      │           ║
║          │  worker.py    │    │  worker.py      │           ║
║          └───────┬───────┘    └────────┬────────┘           ║
║                  │                     │                     ║
║          ┌───────┴─────────────────────┴───────┐            ║
║          │                                      │            ║
║   generator.py        browser.py        crash_handler.py    ║
║  (Claude + UCB1 +   (Firefox ASan +    (detect + triage     ║
║   brief injection)   --screenshot)      + minimize + report) ║
║          │                                      │            ║
║   novelty.py                          subsystem_tracker.py  ║
║  (TF-IDF dedup,                      (18 subsystems,        ║
║   shared corpus)                      shared across workers) ║
║                                                │            ║
║                                          storage.py         ║
║                                      (crash artifacts)      ║
║                                                │            ║
║                                    ┌───────────┴───────┐   ║
║                                    │                   │   ║
║                                 api.py           dashboard/ ║
║                                (REST)             (React UI) ║
║                                                              ║
║  ┌──────────────────────────────────────────────────────┐   ║
║  │         watch.py  (cron every 2 hours)                │   ║
║  │  metrics → Claude analysis → auto-fix → Telegram     │   ║
║  └──────────────────────────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════╝
                               ║  feedback/*.json
                               ▼
╔══════════════════════════════════════════════════════════════╗
║          REDBOX PROTOCOL (feedback loop)                     ║
║  (crash results refine future research directions)           ║
╚══════════════════════════════════════════════════════════════╝
```

### Shared State

All workers share three thread-safe objects created by `main.py`:

| Object | Purpose | Thread Safety |
|---|---|---|
| `CrashDeduplicator` | Prevents duplicate crash reports across workers | `threading.Lock` on signature cache |
| `SubsystemTracker` | Tracks test/crash counts per subsystem, steers coverage | `threading.RLock` on counters |
| `NoveltyTracker` | TF-IDF corpus for semantic deduplication | `threading.Lock` on corpus + vectorizer |

## Redbox Protocol Integration

Blackbox Protocol is designed to receive **attack briefs** from [Redbox Protocol](../redbox-protocol/), which reads actual Firefox C++ source code and identifies specific vulnerability hypotheses.

### How It Works

1. **Redbox** researches Firefox C++ source, finds a potentially vulnerable code pattern, and writes a brief to `redbox-protocol/briefs/`
2. **Worker** checks for pending briefs before each test cycle
3. If a brief is available, it's atomically claimed (renamed `.processing`) so no two workers test the same brief
4. The worker's LLM prompt is prepended with the brief's C++ target, vulnerability hypothesis, source evidence, and suggested trigger sequence — giving Claude precise context to generate targeted test cases
5. After the test completes, the worker writes a feedback JSON to `redbox-protocol/feedback/`
6. **Redbox** reads feedback, updates its knowledge store, and refines future research

### Brief Format

Briefs written by Redbox (consumed by workers):

```json
{
  "brief_id": "20260323_143000_jit_uaf",
  "created_at": "2026-03-23T14:30:00Z",
  "priority": "high",
  "target": {
    "class": "ScalarReplacement",
    "method": "IsObjectEscaped",
    "file": "js/src/jit/ScalarReplacement.cpp",
    "lines": "280-310"
  },
  "vulnerability": {
    "class": "type_confusion",
    "hypothesis": "PostWriteBarrier at line 284 doesn't check operand index, potentially allowing incorrect escape analysis leading to type confusion",
    "source_evidence": "// Line 284: PostWriteBarrier(block, ins, /* index */ 0);\n// ← does not validate index against actual operand count",
    "related_cve": "CVE-2024-29943"
  },
  "trigger": {
    "sequence": "1. Create array with known element types\n2. JIT compile a hot function\n3. During compilation, trigger scalar replacement on an object\n4. Cause type change that invalidates the escape analysis",
    "js_hint": "Array operations + heavy allocation to force JIT + type-changing writes"
  },
  "confidence": "medium"
}
```

### Feedback Format

Workers write feedback after testing (consumed by Redbox):

```json
{
  "brief_id": "20260323_143000_jit_uaf",
  "result": "crash",
  "crash_id": "20260323_151234_w1_t42",
  "severity": 5,
  "asan_output": "ERROR: AddressSanitizer: heap-use-after-free ...",
  "stack_trace": "#0 0x... in ScalarReplacement::IsObjectEscaped ..."
}
```

### Configuration

Add these paths to `config.json` to enable integration:

```json
{
  "briefs_dir": "/home/ubuntu/redbox-protocol/briefs",
  "feedback_dir": "/home/ubuntu/redbox-protocol/feedback"
}
```

## Prerequisites

- **Python 3.10+**
- **Node.js 18+** and npm (for the dashboard)
- **Firefox ASan build** (AddressSanitizer-instrumented, strongly recommended)
- **Anthropic API key** (or a compatible proxy endpoint)
- **Xvfb** (for headless Linux operation)
- **Claude Code** (optional, for autonomous fix application via `watch.py`)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/blackbox-protocol.git
cd blackbox-protocol
```

### 2. Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Install dashboard dependencies

```bash
cd dashboard
npm install
cd ..
```

### 4. Install Firefox ASan build

For best results, use an **ASan (AddressSanitizer) build** of Firefox. Install with [fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch):

```bash
pip install fuzzfetch
fuzzfetch --asan --fuzzing -n firefox-asan
```

This downloads a Firefox build instrumented with AddressSanitizer, UndefinedBehaviorSanitizer, and debug assertions — essential for detecting memory corruption that would silently succeed on release builds.

### 5. Configure environment variables

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=sk-your-api-key-here
ANTHROPIC_BASE_URL=https://api.anthropic.com
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id
```

To get Telegram credentials:
- **Bot token** -- Message `@BotFather` on Telegram, run `/newbot`
- **Chat ID** -- Message `@userinfobot` on Telegram, run `/start`

### 6. Set the Firefox path

Edit `config.json` and set `firefox_path` to your Firefox binary:

```json
{
  "firefox_path": "/home/ubuntu/blackbox-protocol/firefox-asan/firefox"
}
```

### 7. Unified startup (recommended)

Use the unified startup script at `/home/ubuntu/start-all.sh` to launch the entire pipeline (Xvfb + fuzzer workers + verifier + dashboard + Redbox research agent):

```bash
cd /home/ubuntu
./start-all.sh          # Start everything
./start-all.sh status   # Check status of all components
./start-all.sh stop     # Stop all pipeline sessions
```

## Configuration

All settings live in `config.json`:

| Key | Default | Description |
|---|---|---|
| `workers` | `2` | Number of parallel fuzzing workers |
| `timeout_seconds` | `20` | Max time Firefox runs per test case |
| `delay_between_tests` | `1` | Seconds between test generations |
| `min_save_severity` | `2` | Minimum severity to save (1-5). Below this threshold, findings are logged but not saved |
| `api_port` | `6767` | REST API server port |
| `dashboard_port` | `6868` | Dashboard server port |
| `crashes_dir` | `"crashes"` | Output directory for crash artifacts |
| `briefs_dir` | `"/home/ubuntu/redbox-protocol/briefs"` | Directory to read attack briefs from Redbox |
| `feedback_dir` | `"/home/ubuntu/redbox-protocol/feedback"` | Directory to write test results back to Redbox |
| `novelty_threshold` | `0.65` | TF-IDF similarity cutoff (higher = stricter dedup) |
| `novelty_max_corpus` | `500` | Max test cases retained for novelty comparison |
| `plateau_window` | `20` | Sliding window size for stall detection |
| `plateau_threshold` | `0.05` | Minimum novelty rate before diversity injection |
| `subsystem_underexplored_top_n` | `3` | Number of underexplored subsystems to hint per generation |
| `history_max_turns` | `6` | LLM conversation history length per worker |
| `use_xvfb` | `true` | Use Xvfb virtual display on Linux |
| `xvfb_display` | `":99"` | Xvfb display number |
| `auto_open_dashboard` | `false` | Auto-open dashboard in browser on start |
| `claude_code_auto_apply` | `false` | Let `watch.py` invoke Claude Code to apply suggested code changes |

### Severity filtering

Set `min_save_severity` to control which findings are saved:

| Value | Saves |
|---|---|
| `1` | Everything (including timeouts) |
| `2` | Errors and above (default — filters out pure timeouts) |
| `3` | Medium+ crashes, segfaults, ASan findings |
| `4` | Only segfaults and ASan findings (recommended for bug bounty) |
| `5` | Only critical ASan findings |

### Crash detection keywords

Three keyword lists control crash detection:

- **`crash_keywords`** -- Patterns scanned in Firefox's stdout/stderr to detect crashes. Includes sanitizer markers, signal names, Mozilla assertion macros (`MOZ_CRASH`, `MOZ_ASSERT`, etc.), and ASAN `Scariness:` scores
- **`asan_keywords`** -- High-value sanitizer patterns that automatically set severity to 5 (Critical). Covers AddressSanitizer, ThreadSanitizer, MemorySanitizer, and UndefinedBehaviorSanitizer
- **`ignore_keywords`** -- Known false positives filtered out (GPU warnings, sandbox messages, X11 noise, GLib warnings, etc.). Sanitizer crashes bypass ignore filters

### Sanitizer environment

The fuzzer configures aggressive sanitizer settings for maximum detection:

```
ASAN_OPTIONS:
  quarantine_size_mb=64     # Delays memory reuse → catches late UAFs
  redzone=512               # Large guard zones → catches small OOB
  malloc_fill_byte=190      # 0xBE fill on alloc → recognizable uninit reads
  free_fill_byte=206        # 0xCE fill on free → recognizable UAF reads
  detect_stack_use_after_return=1
  print_scariness=1         # ASAN exploitability score (0-100)
  malloc_context_size=30    # Deep stack traces in reports
  detect_container_overflow=1
  strict_string_checks=1
  check_initialization_order=1

UBSAN_OPTIONS: print_stacktrace=1:halt_on_error=1
TSAN_OPTIONS:  report_bugs=1
LSAN_OPTIONS:  detect_leaks=0

Firefox-specific:
  XPCOM_DEBUG_BREAK=stack-and-abort   # Makes NS_ASSERTION fatal
  MOZ_CRASHREPORTER_DISABLE=1        # Prevents crash dialog from blocking
  MOZ_GDB_SLEEP=0                    # No debugger attach delay
```

## Usage

### Quick Start — Unified Pipeline

```bash
cd /home/ubuntu
./start-all.sh
```

This starts the entire pipeline: Xvfb, Blackbox fuzzer (2 workers), crash verifier, dashboard + API server, and Redbox research agent.

### Manual Start

Open three terminals:

**Terminal 1 — API Server**

```bash
cd blackbox-protocol
source venv/bin/activate
python api.py
```

**Terminal 2 — Dashboard**

```bash
cd blackbox-protocol/dashboard
npm run dev
```

**Terminal 3 — Fuzzer**

```bash
cd blackbox-protocol
source venv/bin/activate
python main.py
```

The fuzzer will:

1. Test API connectivity
2. Clean up stale Firefox processes
3. Spawn 2 worker threads (each with a different initial prompt)
4. Check for pending attack briefs from Redbox Protocol
5. Begin generating and executing test cases

Press `Ctrl+C` to stop the fuzzer gracefully.

### Monitoring

```bash
# Watch live fuzzer output
tail -f logs/fuzzer.log

# Check all component status
./start-all.sh status

# Attach to a tmux session
tmux attach -t fuzzer
tmux attach -t redbox
tmux attach -t verifier

# Stop everything
./start-all.sh stop
```

### Output

```
============================================================
FIREFOX FUZZER - Modular Edition
============================================================
Workers: 2
Firefox: Mozilla Firefox 137.0
Crashes dir: /home/user/blackbox-protocol/crashes
Dashboard: http://localhost:6868
Novelty threshold: 0.65
============================================================

[Worker 1] Starting...
[Worker 2] Starting...
[W1 | T#1 | strategy:use_after_free | subsystem:Web_Animations | novelty:1.00] → OK
[W2 | T#1 | brief:20260323_143000_jit_uaf | subsystem:JIT | novelty:1.00] → CRASH sev:5 sig:a3f29b1c
  Crash ID: 20260323_142105_w2_t1
  Files saved to crashes/
```

## Dashboard

Access the web dashboard at **http://localhost:6868** after starting the API and dashboard servers.

### Features

- **Stats overview** -- Total crashes, severity distribution, strategy effectiveness, subsystem coverage
- **Crash table** -- Sortable, filterable list of all discovered crashes with severity indicators
- **Filtering** -- Filter by severity level, status, strategy, and subsystem
- **Search** -- Text search across crash IDs, issue reasons, strategies, and subsystems
- **Sorting** -- Click column headers to sort by severity or time
- **Bulk actions** -- Select multiple crashes for bulk status changes or deletion
- **Delete** -- Remove crashes individually or in bulk with confirmation dialogs
- **Crash detail view** -- Tabbed interface showing:
  - AI-generated Bugzilla-ready bug report
  - Minimized HTML reproducer
  - Original generated test case
  - Raw Firefox/ASAN output
  - Crash metadata (strategy, subsystem, severity, signature, timestamps)
- **Status management** -- Mark crashes as `new`, `verified`, `ignored`, or `submitted`
- **Auto-refresh** -- Polls the API every 5 seconds for new crashes
- **Dark/light theme** toggle

## API Endpoints

The REST API runs on port `6767` by default.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/crashes` | List all crashes with metadata |
| `GET` | `/api/crashes/{crash_id}` | Get detailed crash info with file contents |
| `PATCH` | `/api/crashes/{crash_id}` | Update crash status or notes |
| `DELETE` | `/api/crashes/{crash_id}` | Delete a crash and all its artifacts |
| `PATCH` | `/api/crashes/bulk/status` | Bulk update status for multiple crashes |
| `POST` | `/api/crashes/bulk/delete` | Bulk delete multiple crashes |
| `GET` | `/api/stats` | Summary statistics with strategy and subsystem breakdowns |

## How It Works

### Fuzzing Loop

Each worker runs this cycle continuously:

```
1.  CHECK BRIEFS    →  Look for pending attack brief from Redbox Protocol
                        (atomic claim — only one worker per brief)
2.  SELECT STRATEGY →  UCB1 bandit picks the most promising attack vector
                        (falls back to general strategies if no brief)
3.  IDENTIFY TARGETS→  Shared subsystem tracker highlights underexplored areas
4.  CHECK PLATEAU   →  If novelty rate is low, inject diversity prompt + rotate subsystem
5.  GENERATE TEST   →  Claude (red-team persona) creates surgical HTML/JS test case
                        (if brief active: brief context prepended → highly targeted)
6.  NOVELTY FILTER  →  TF-IDF checks similarity against shared corpus across all workers
7.  EXECUTE         →  Firefox ASan build loads test via --screenshot /dev/null (~8s)
8.  DETECT CRASH    →  Scan stdout/stderr for ASAN, UBSAN, TSAN, MOZ_CRASH keywords
9.  SEVERITY RATING →  Parse ASAN Scariness score + exploitability signals → severity 1-5
10. SEVERITY CHECK  →  Skip saving if below min_save_severity threshold
11. TRIAGE          →  Deduplicate via stack signature, minimize, generate Bugzilla report
12. STORE           →  Save all artifacts to crashes/{crash_id}/
13. FEEDBACK        →  Write result to redbox-protocol/feedback/ (if brief was active)
```

### Brief-Guided Test Generation

When a worker claims a brief, its generation prompt becomes two-part:

```
[ATTACK BRIEF — HIGH PRIORITY]
Target: ScalarReplacement::IsObjectEscaped
File: js/src/jit/ScalarReplacement.cpp
Vulnerability: type_confusion
Hypothesis: PostWriteBarrier at line 284 doesn't check operand index...
Source evidence:
    // Line 284: PostWriteBarrier(block, ins, /* index */ 0);
Suggested trigger:
    1. Create array with known element types
    2. JIT compile a hot function
    ...

[GENERAL STRATEGY]
You are an elite security researcher...
```

This gives Claude the specific C++ context it needs to write highly targeted test cases, rather than guessing blindly from strategy templates.

### Multi-Armed Bandit (UCB1)

The fuzzer treats strategy selection as an exploration-exploitation tradeoff. Each strategy tracks its uses and crash discoveries. The UCB1 formula balances:
- **Exploitation**: strategies with higher crash rates get selected more often
- **Exploration**: untested or under-tested strategies get a bonus

Strategy selection is **atomic** — the lock is held during both selection and use-count increment, preventing multiple workers from picking the same untested strategy simultaneously.

### Red-Team System Prompt

The LLM operates under a detailed security researcher persona that includes:
- **Gecko C++ internals** -- Specific class names (nsIFrame, PresShell, AnimationTimeline, txXPathNodeUtils, WasmStructObject), method signatures, and invariant descriptions
- **Real CVE patterns** -- 7 template patterns from actual Firefox CVEs (2024-9680, 2024-29943, 2025-1009, 2024-8381, etc.) that the model mutates and combines
- **Surgical methodology** -- Every test case must include a comment block specifying Target (C++ class/method), Property (violated invariant), Mechanism (step-by-step trigger), and Expected (crash signature)
- **Anti-patterns** -- Explicitly prohibits random fuzz, resource exhaustion, and pattern repetition

### Novelty Detection

Before executing a test case, the fuzzer computes its TF-IDF vector (using character 3-6 n-grams, 5000 max features) and measures cosine similarity against a rolling corpus shared across all workers. Tests above the similarity threshold are discarded, ensuring each execution tests genuinely new code patterns. The shared corpus prevents different workers from independently generating similar test cases.

### Exploitability-Aware Severity

Crash severity is automatically boosted based on exploitability signals:

| Signal | Severity |
|---|---|
| ASAN Scariness ≥ 60 | → 5 (Critical) |
| Write-class bugs (write, double-free) | → 5 (Critical) |
| UAF, type confusion, heap-buffer-overflow | → 5 (Critical) |
| Stack-buffer-overflow + write | → 5 (Critical) |
| MOZ_CRASH / MOZ_ASSERT / NS_ASSERTION | → 4 (High) |
| ASAN Scariness ≥ 40 | → 4 (High) |
| SIGSEGV / segfault | → 4 (High) |

### Crash Triage Pipeline

When a crash is detected (and meets the severity threshold):

1. **Deduplication** -- Normalize top 10 stack frames (strip addresses, normalize numbers), MD5 hash, check against in-memory cache and on-disk crash metadata
2. **Minimization** -- Claude (Opus) reduces the test case to the smallest reproducer that still triggers the same bug
3. **Report generation** -- Claude (Opus) writes a professional Bugzilla-ready bug report with summary, affected component, steps to reproduce, technical analysis, and security impact assessment
4. **Storage** -- All artifacts saved in a per-crash subdirectory (minimized HTML, original HTML, report, raw Firefox output, metadata JSON)

## Fuzzing Strategies

11 attack strategies target distinct vulnerability classes, each informed by real CVE patterns:

| Strategy | Target | Technique | CVE Reference |
|---|---|---|---|
| `use_after_free` | DOM engine | Remove nodes, access freed nsIFrame pointers via MutationObserver re-entrancy | General UAF class |
| `gc_pressure` | SpiderMonkey GC | Force GC during raw pointer use, stale references via FinalizationRegistry | CVE-2024-7527 |
| `type_confusion` | JIT compiler | Shape transitions, Proxy traps, `with` statement scope confusion | CVE-2024-8381 |
| `layout_uaf` | Layout engine | DOM mutation during ResizeObserver/reflow, frame destruction races | PresShell re-entrancy |
| `buffer_detach` | TypedArrays | Transfer ArrayBuffer via postMessage during iteration, WASM memory growth | Buffer detach class |
| `iframe_lifecycle` | Document lifecycle | Access freed nsDocument/nsGlobalWindowInner after iframe removal | Browsing context UAF |
| `web_api_native` | Web APIs | Use native API wrappers after backing C++ objects are destroyed | CVE-2025-1930 |
| `animation_lifecycle` | Web Animations | Cancel/remove animations during AnimationTimeline::Tick iteration | CVE-2024-9680 |
| `xslt_xpath` | XSLT/XPath | Modify source document during XSLTProcessor transformation | CVE-2025-1009/3028 |
| `wasm_type_boundary` | WebAssembly | GC proposal type confusion (structref/arrayref/i31ref), exception UAF | CVE-2024-8385 |
| `jit_range_analysis` | JIT Range Analysis | Violate range analysis proofs via array length mutation after JIT compilation | CVE-2024-29943 |

## Tracked Subsystems

The fuzzer monitors coverage across 18 Firefox subsystems and prioritizes underexplored ones:

| Subsystem | Description |
|---|---|
| HTML5_parser | HTML parsing and DOM construction |
| CSS_layout | Style computation and layout |
| JS_engine | SpiderMonkey JavaScript engine |
| SVG_renderer | SVG rendering pipeline |
| Canvas_WebGL | Canvas 2D and WebGL contexts |
| Web_Audio | Web Audio API processing |
| WebRTC | Real-time communication APIs |
| DOM_events | Event handling and dispatch |
| IndexedDB | Client-side database |
| WebAssembly | Wasm compilation and execution |
| CSS_animations | CSS transitions and animations |
| Shadow_DOM | Shadow DOM and web components |
| Intersection_Observer | Intersection Observer API |
| Service_Worker | Service Worker lifecycle |
| WebSockets | WebSocket connections |
| Web_Animations | Web Animations API (CVE-2024-9680 surface) |
| XSLT_XPath | XSLT/XPath processing (CVE-2025-1009 surface) |
| WebTransport | WebTransport protocol lifecycle |

## Crash Output

Each crash is saved in its own subdirectory under `crashes/`:

```
crashes/
├── 20260322_193432_w1_t1/
│   ├── meta.json           # Metadata (severity, strategy, subsystem, signature, timestamps)
│   ├── original.html       # Full generated test case
│   ├── minimized.html      # Minimal reproducer (Claude-minimized)
│   ├── report.txt          # Bugzilla-ready bug report
│   └── output.txt          # Raw Firefox stdout/stderr (ASAN traces, assertions)
```

### meta.json structure

```json
{
  "crash_id": "20260322_193432_w1_t1",
  "timestamp": "2026-03-22T19:34:32.123456",
  "worker_id": 1,
  "test_num": 1,
  "issue_reason": "non-zero exit (-6)",
  "severity": 5,
  "status": "new",
  "html_file": "minimized.html",
  "report_file": "report.txt",
  "original_file": "original.html",
  "output_snippet": "=ERROR: AddressSanitizer: heap-use-after-free ...",
  "signature": "a3f29b1c4d5e6f7890123456789abcde",
  "strategy_name": "animation_lifecycle",
  "subsystem": "Web_Animations",
  "novelty_skips": 2,
  "firefox_version": "Mozilla Firefox 137.0",
  "brief_id": "20260323_143000_jit_uaf"
}
```

### Severity Levels

| Level | Label | Trigger | Auto-Boost |
|---|---|---|---|
| 5 | Critical | AddressSanitizer findings (UAF, heap overflow, double-free) | Write bugs, ASAN Scariness ≥ 60 |
| 4 | High | SIGSEGV, segfault, MOZ_CRASH, MOZ_ASSERT | ASAN Scariness ≥ 40, assertion failures |
| 3 | Medium | Generic crashes, aborts | — |
| 2 | Low | Errors, non-zero exit codes | — |
| 1 | Info | Timeouts (potential DoS) | — |

## Project Structure

```
blackbox-protocol/
├── main.py                    # Entry point — loads config, creates shared state, spawns workers
├── worker.py                  # Fuzzing loop — UCB1, brief consumption, feedback writing
├── watch.py                   # Monitoring tool — metrics, Claude analysis, Telegram alerts
├── verify.py                  # Crash verification daemon
├── api.py                     # FastAPI REST server for crash management
├── config.json                # All tunable parameters
├── requirements.txt           # Python dependencies
├── start.sh                   # Linux launcher (venv, Xvfb, log rotation, tee)
├── .env                       # API + Telegram credentials (not committed)
│
├── modules/                   # Core fuzzing engine
│   ├── browser.py             # Firefox process management, ASAN/UBSAN/TSAN env, --screenshot
│   ├── generator.py           # Red-team system prompt, 11 strategies, UCB1 with atomic lock
│   ├── crash_handler.py       # Crash detection, exploitability scoring, dedup, minimization
│   ├── novelty.py             # TF-IDF semantic deduplication (shared across workers)
│   ├── plateau_detector.py    # Stall detection + diversity injection
│   ├── subsystem_tracker.py   # 18 Firefox subsystem coverage stats (shared across workers)
│   └── storage.py             # Crash artifact persistence (5 files per crash)
│
├── utils/                     # Helpers
│   └── html_utils.py          # HTML extraction from LLM output
│
├── dashboard/                 # React web UI
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx            # Router + layout
│       └── components/
│           ├── CrashList.jsx  # Crash table with filters, search, bulk actions
│           ├── CrashDetail.jsx# Detailed crash view with delete
│           └── Stats.jsx      # Statistics, strategy charts, subsystem coverage
│
├── briefs/                    # Attack briefs from Redbox Protocol (auto-consumed by workers)
│   ├── {timestamp}_{target}.json       # Pending brief (worker will claim this)
│   ├── {timestamp}_{target}.processing # Being tested by a worker
│   └── processed/
│       └── {timestamp}_{target}.json   # Completed briefs
│
├── feedback/                  # Results written back to Redbox Protocol
│   └── {brief_id}_result.json
│
├── logs/                      # Runtime logs (created automatically)
│   ├── fuzzer.log             # Main fuzzer output (via tee)
│   ├── verifier.log           # verify.py crash verification output
│   ├── watcher.log            # watch.py run summaries
│   ├── auto_fixes.log         # Config changes applied by watch.py
│   └── suggestions_*.txt      # Full Claude analysis JSON per run
│
└── crashes/                   # Output directory (per-crash subdirectories)
    └── {crash_id}/
        ├── meta.json          # Crash metadata
        ├── minimized.html     # Minimized reproducer
        ├── original.html      # Original test case
        ├── report.txt         # Bug report
        └── output.txt         # Raw Firefox/ASAN output
```

## Monitoring & Watcher

`watch.py` is a standalone monitoring tool designed to run on a cron schedule. It collects fuzzer metrics, sends them to Claude for analysis, applies safe config changes automatically, and sends Telegram notifications with status updates.

### What it does

1. **Collects data** -- last 200 lines of `logs/fuzzer.log`, recent crash summaries, crash counts by severity/strategy/subsystem, timeout and novelty skip rates, current config and strategies
2. **Calls Claude** (Opus) -- sends all metrics for performance analysis, receives structured JSON with health assessment, auto-fixes, manual fix suggestions, and red flags
3. **Applies auto-fixes** -- safe config.json changes (e.g. adjusting `timeout_seconds`, adding keywords) are applied immediately and logged to `logs/auto_fixes.log`
4. **Sends Telegram** -- status message, attention items (if any), and urgent alerts for critical health
5. **Claude Code auto-apply** (optional) -- if `claude_code_auto_apply` is `true` in config.json, invokes Claude Code to apply suggested code changes and restarts the fuzzer

### Setup

```bash
# Set up the cron job (runs every 2 hours)
crontab -e

# Add this line:
0 */2 * * * cd /home/ubuntu/blackbox-protocol && /home/ubuntu/blackbox-protocol/venv/bin/python3 watch.py >> logs/watcher.log 2>&1
```

## Troubleshooting

### API connectivity fails on startup

```
FAILED: http://your-endpoint/health → <error>
The proxy is not reachable. Fix your ANTHROPIC_BASE_URL in .env
```

Verify your `ANTHROPIC_BASE_URL` in `.env` is correct and the endpoint is reachable.

### Firefox not found

Set `firefox_path` in `config.json` to the full path of your Firefox binary.

### Firefox fails to start (missing libraries)

On headless Linux servers, install required dependencies:

```bash
sudo apt install libgtk-3-0 libdbus-glib-1-2 libasound2 libx11-xcb1 libxt6 xvfb
```

### Firefox hangs / all tests timeout

The fuzzer uses `--screenshot /dev/null` to force Firefox to render and exit. If tests consistently timeout:
- Verify your Firefox binary supports `--screenshot` (ASan builds do)
- Reduce `timeout_seconds` (default: 20s, Firefox typically exits in ~8s)
- Ensure Xvfb is running if `use_xvfb` is `true`

### All crashes show as DUP

This usually means low-severity findings (timeouts, minor errors) are producing identical stack signatures:
- Raise `min_save_severity` to 2 or higher
- Check that `ignore_keywords` covers known noise in your environment
- Delete any bogus saved crashes from `crashes/` directory

### Workers generating identical test cases

If worker logs show the same strategies and subsystems in lockstep:
- Verify you're running the latest code with atomic strategy selection
- Each worker should have a different initial prompt (rotates by worker_id)
- The shared `NoveltyTracker` prevents cross-worker duplication

### No crashes detected

- Use an **ASan build** of Firefox (`pip install fuzzfetch && fuzzfetch --asan --fuzzing -n firefox-asan`)
- Lower `novelty_threshold` (e.g., `0.55`) to allow more test case variations
- Check that Redbox Protocol is producing attack briefs — brief-guided tests are far more likely to crash
- Increase `workers` for higher throughput (2 workers is tuned for 1 deep research session per 8 minutes)

### Dashboard not loading

Make sure the API server (`python api.py`) is running before starting the dashboard. The dashboard proxies requests to `http://localhost:6767`.

## License

This project is intended for authorized security research and testing only. Use responsibly and only against software you have permission to test.
