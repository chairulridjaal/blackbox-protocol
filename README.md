# Blackbox Protocol

AI-powered Firefox browser fuzzer that uses Claude LLM to generate intelligent test cases targeting memory corruption vulnerabilities. The fuzzer combines multi-armed bandit strategy selection, semantic novelty detection, and automated crash triage into a modular, multi-worker framework.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
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
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **LLM-Driven Test Generation** -- Claude generates targeted HTML/JS test cases designed to trigger memory corruption in Firefox
- **Multi-Worker Concurrency** -- Parallel fuzzing workers with shared crash deduplication
- **UCB1 Strategy Selection** -- Multi-armed bandit algorithm balances exploration vs. exploitation across 7 attack strategies
- **Semantic Novelty Detection** -- TF-IDF cosine similarity filters out duplicate test cases before execution
- **Plateau Detection** -- Automatically detects when the fuzzer stalls and injects diversity prompts
- **Subsystem Coverage Tracking** -- Monitors 15 Firefox subsystems and steers generation toward underexplored areas
- **Automated Crash Minimization** -- Uses Claude to reduce crashing test cases to minimal reproducers
- **Bug Report Generation** -- Produces Bugzilla-ready reports with root cause analysis
- **Crash Deduplication** -- MD5-based stack trace normalization prevents duplicate reports
- **Severity Filtering** -- Configurable minimum severity threshold skips low-value findings (timeouts, minor errors)
- **Web Dashboard** -- React-based UI with filtering, search, sorting, bulk actions, and real-time crash triage
- **REST API** -- FastAPI backend for crash management, bulk operations, and statistics

## Architecture

```
                        +-------------------+
                        |     main.py       |
                        |  (orchestrator)   |
                        +--------+----------+
                                 |
                    +------------+------------+
                    |                         |
             +------+------+          +------+------+
             |  Worker 1   |          |  Worker 2   |
             |  worker.py  |          |  worker.py  |
             +------+------+          +------+------+
                    |                         |
        +-----------+-----------+             |
        |           |           |             |
   generator   browser    crash_handler       |
   (Claude)    (Firefox)  (detect+triage)     |
        |           |           |             |
        +-----+-----+-----+----+-------------+
              |           |
         novelty      subsystem_tracker
        (TF-IDF)     (coverage stats)
              |           |
              +-----+-----+
                    |
               storage.py
             (crash artifacts)
                    |
              +-----+-----+
              |           |
           api.py    dashboard/
          (REST)     (React UI)
```

## Prerequisites

- **Python 3.10+**
- **Node.js 18+** and npm (for the dashboard)
- **Firefox** installed locally (ASan build recommended)
- **Anthropic API key** (or a compatible proxy endpoint)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/blackbox-protocol.git
cd blackbox-protocol
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install dashboard dependencies

```bash
cd dashboard
npm install
cd ..
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=sk-your-api-key-here
ANTHROPIC_BASE_URL=https://api.anthropic.com
```

### 5. Set the Firefox path

Edit `config.json` and set `firefox_path` to your Firefox binary:

```json
{
  "firefox_path": "C:/Program Files/Mozilla Firefox/firefox.exe"
}
```

Common paths:
| OS | Path |
|---|---|
| Windows | `C:/Program Files/Mozilla Firefox/firefox.exe` |
| macOS | `/Applications/Firefox.app/Contents/MacOS/firefox` |
| Linux | `/usr/bin/firefox` |

For best results, use an **ASan (AddressSanitizer) build** of Firefox. Install with [fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch):

```bash
pip install fuzzfetch
fuzzfetch --asan -o ~/firefox-asan
```

Then set:

```json
{
  "firefox_path": "/home/your-user/firefox-asan/firefox/firefox"
}
```

## Configuration

All settings live in `config.json`:

| Key                             | Default     | Description                                                                 |
| ------------------------------- | ----------- | --------------------------------------------------------------------------- |
| `workers`                       | `2`         | Number of parallel fuzzing workers                                          |
| `timeout_seconds`               | `30`        | Max time Firefox runs per test case                                         |
| `delay_between_tests`           | `180`       | Seconds between test generations (rate limiting)                            |
| `min_save_severity`             | `3`         | Minimum severity to save (1-5). Crashes below this are logged but not saved |
| `api_port`                      | `6767`      | REST API server port                                                        |
| `dashboard_port`                | `5173`      | Vite dev server port                                                        |
| `crashes_dir`                   | `"crashes"` | Output directory for crash artifacts                                        |
| `novelty_threshold`             | `0.82`      | TF-IDF similarity cutoff (higher = stricter dedup)                          |
| `novelty_max_corpus`            | `500`       | Max test cases retained for novelty comparison                              |
| `plateau_window`                | `20`        | Sliding window size for stall detection                                     |
| `plateau_threshold`             | `0.05`      | Minimum novelty rate before diversity injection                             |
| `subsystem_underexplored_top_n` | `3`         | Number of underexplored subsystems to hint                                  |
| `history_max_turns`             | `6`         | LLM conversation history length                                             |
| `use_xvfb`                      | `true`      | Use virtual display on Linux (headless)                                     |
| `xvfb_display`                  | `":99"`     | Xvfb display number                                                         |
| `auto_open_dashboard`           | `false`     | Auto-open dashboard in browser on start                                     |

### Severity filtering

Set `min_save_severity` to control which findings are saved:

| Value | Saves                                                         |
| ----- | ------------------------------------------------------------- |
| `1`   | Everything (including timeouts)                               |
| `3`   | Medium+ crashes, segfaults, ASan findings                     |
| `4`   | Only segfaults and ASan findings (recommended for bug bounty) |
| `5`   | Only ASan findings                                            |

### Crash detection keywords

`crash_keywords` and `asan_keywords` define patterns scanned in Firefox's stdout/stderr to detect crashes. `ignore_keywords` filters out known false positives (GPU warnings, sandbox messages, etc.).

## Usage

### Quick Start (Windows)

```bash
start.bat
```

This launches the API server, dashboard, and fuzzer in separate terminal windows.

### Manual Start

Open three terminals:

**Terminal 1 -- API Server**

```bash
python api.py
```

**Terminal 2 -- Dashboard**

```bash
cd dashboard
npm run dev
```

**Terminal 3 -- Fuzzer**

```bash
python main.py
```

The fuzzer will:

1. Test API connectivity
2. Clean up stale Firefox processes
3. Spawn worker threads
4. Begin generating and executing test cases

Press `Ctrl+C` to stop the fuzzer gracefully.

### Linux Setup

```bash
# Install Xvfb for headless display
sudo apt install xvfb

# Start virtual display
Xvfb :99 &
export DISPLAY=:99

# Run the fuzzer
python main.py
```

### Output

The fuzzer logs activity to stdout:

```
============================================================
FIREFOX FUZZER - Modular Edition
============================================================
Workers: 2
Crashes dir: /home/user/blackbox-protocol/crashes
Dashboard: http://localhost:5173
Novelty threshold: 0.82
Plateau window: 20
============================================================

Testing API connectivity...
  http://your-api-endpoint/health → 200 OK
Press Ctrl+C to stop
```

## Dashboard

Access the web dashboard at **http://localhost:5173** after starting the API and dashboard servers.

### Features

- **Stats overview** -- Total crashes, severity distribution, strategy effectiveness, subsystem coverage
- **Crash table** -- Sortable, filterable list of all discovered crashes with severity indicators
- **Filtering** -- Filter by severity level, status, strategy, and subsystem
- **Search** -- Text search across crash IDs, issue reasons, strategies, and subsystems
- **Sorting** -- Click column headers to sort by severity or time
- **Bulk actions** -- Select multiple crashes for bulk status changes or deletion
- **Delete** -- Remove crashes individually or in bulk with confirmation dialogs
- **Crash detail view** -- Tabbed interface showing:
  - AI-generated bug report
  - Minimized HTML reproducer
  - Original generated test case
  - Crash metadata (strategy, subsystem, severity, timestamps)
- **Status management** -- Mark crashes as `new`, `verified`, `ignored`, or `submitted`
- **Auto-refresh** -- Polls the API every 5 seconds for new crashes
- **Dark/light theme** toggle

## API Endpoints

The REST API runs on port `6767` by default.

| Method   | Endpoint                   | Description                                               |
| -------- | -------------------------- | --------------------------------------------------------- |
| `GET`    | `/api/crashes`             | List all crashes with metadata                            |
| `GET`    | `/api/crashes/{crash_id}`  | Get detailed crash info with file contents                |
| `PATCH`  | `/api/crashes/{crash_id}`  | Update crash status or notes                              |
| `DELETE` | `/api/crashes/{crash_id}`  | Delete a crash and all its artifacts                      |
| `PATCH`  | `/api/crashes/bulk/status` | Bulk update status for multiple crashes                   |
| `POST`   | `/api/crashes/bulk/delete` | Bulk delete multiple crashes                              |
| `GET`    | `/api/stats`               | Summary statistics with strategy and subsystem breakdowns |

### Examples

```bash
# List all crashes
curl http://localhost:6767/api/crashes

# Get crash details
curl http://localhost:6767/api/crashes/20260322_193432_w1_t1

# Mark a crash as verified
curl -X PATCH http://localhost:6767/api/crashes/20260322_193432_w1_t1 \
  -H "Content-Type: application/json" \
  -d '{"status": "verified"}'

# Delete a crash
curl -X DELETE http://localhost:6767/api/crashes/20260322_193432_w1_t1

# Bulk update status
curl -X PATCH http://localhost:6767/api/crashes/bulk/status \
  -H "Content-Type: application/json" \
  -d '{"crash_ids": ["20260322_193432_w1_t1", "20260322_193500_w2_t3"], "status": "verified"}'

# Bulk delete
curl -X POST http://localhost:6767/api/crashes/bulk/delete \
  -H "Content-Type: application/json" \
  -d '{"crash_ids": ["20260322_193432_w1_t1"]}'
```

## How It Works

### Fuzzing Loop

Each worker runs this cycle continuously:

```
1. SELECT STRATEGY    →  UCB1 bandit picks the most promising attack vector
2. IDENTIFY TARGETS   →  Subsystem tracker highlights underexplored areas
3. CHECK PLATEAU      →  If novelty rate is low, inject diversity prompt
4. GENERATE TEST      →  Claude creates an HTML/JS test case
5. NOVELTY FILTER     →  TF-IDF checks similarity against past tests
6. EXECUTE            →  Firefox loads the test case headless
7. DETECT CRASH       →  Scan stdout/stderr for crash keywords
8. SEVERITY CHECK     →  Skip saving if below min_save_severity threshold
9. TRIAGE             →  Deduplicate, minimize, generate report
10. STORE             →  Save all artifacts to crashes/{crash_id}/
11. FEEDBACK          →  Report results back to Claude for next iteration
```

### Multi-Armed Bandit (UCB1)

The fuzzer treats strategy selection as an exploration-exploitation tradeoff. Strategies that produce crashes get higher selection probability, but untested strategies also get explored. This converges on the most effective attack patterns for the target Firefox build.

### Novelty Detection

Before executing a test case, the fuzzer computes its TF-IDF vector (using character 3-6 n-grams) and measures cosine similarity against a rolling corpus of previous tests. Tests above the similarity threshold are discarded, ensuring each execution tests genuinely new code patterns.

### Crash Triage Pipeline

When a crash is detected (and meets the severity threshold):

1. **Deduplication** -- Normalize and hash the stack trace; skip if already seen
2. **Minimization** -- Claude reduces the test case to the smallest reproducer
3. **Report generation** -- Claude (Opus) writes a professional bug report with root cause analysis
4. **Storage** -- All artifacts saved in a per-crash subdirectory

## Fuzzing Strategies

| Strategy           | Target             | Technique                                            |
| ------------------ | ------------------ | ---------------------------------------------------- |
| `use_after_free`   | DOM engine         | Remove nodes, then access freed references           |
| `gc_pressure`      | Garbage collector  | Force GC during sensitive object operations          |
| `type_confusion`   | JIT compiler       | Deoptimize JIT via Proxy traps and shape transitions |
| `layout_uaf`       | Layout engine      | Mutate DOM during layout/reflow callbacks            |
| `buffer_detach`    | TypedArrays        | Transfer ArrayBuffer ownership during reads          |
| `iframe_lifecycle` | Document lifecycle | Race conditions during iframe creation/destruction   |
| `web_api_native`   | Web APIs           | Use native APIs after associated objects are closed  |

## Crash Output

Each crash is saved in its own subdirectory under `crashes/`:

```
crashes/
├── 20260322_193432_w1_t1/
│   ├── meta.json           # Metadata (severity, strategy, subsystem, timestamps)
│   ├── original.html       # Full generated test case
│   ├── minimized.html      # Minimal reproducer
│   └── report.txt          # Bugzilla-ready bug report
├── 20260322_193500_w2_t3/
│   ├── meta.json
│   ├── minimized.html
│   ├── original.html
│   └── report.txt
```

### Severity Levels

| Level | Label    | Trigger                                                   |
| ----- | -------- | --------------------------------------------------------- |
| 5     | Critical | AddressSanitizer findings (use-after-free, heap overflow) |
| 4     | High     | SIGSEGV, segfault, access violation                       |
| 3     | Medium   | Generic crashes, aborts                                   |
| 2     | Low      | Errors, assertions                                        |
| 1     | Info     | Timeouts (potential DoS)                                  |

## Project Structure

```
blackbox-protocol/
├── main.py                    # Entry point -- loads config, spawns workers
├── worker.py                  # Fuzzing loop for each worker thread
├── api.py                     # FastAPI REST server for crash management
├── config.json                # All tunable parameters
├── requirements.txt           # Python dependencies
├── start.bat                  # Windows one-click launcher
├── .env                       # API credentials (not committed)
│
├── modules/                   # Core fuzzing engine
│   ├── browser.py             # Firefox process management
│   ├── generator.py           # LLM test case generation + UCB1
│   ├── crash_handler.py       # Crash detection, dedup, minimization
│   ├── novelty.py             # TF-IDF semantic deduplication
│   ├── plateau_detector.py    # Stall detection + diversity injection
│   ├── subsystem_tracker.py   # Firefox subsystem coverage stats
│   └── storage.py             # Crash artifact persistence
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
└── crashes/                   # Output directory (per-crash subdirectories)
    └── {crash_id}/
        ├── meta.json          # Crash metadata
        ├── minimized.html     # Minimized reproducer
        ├── original.html      # Original test case
        └── report.txt         # Bug report
```

## Tracked Subsystems

The fuzzer monitors coverage across these Firefox subsystems and prioritizes underexplored ones:

| Subsystem             | Description                       |
| --------------------- | --------------------------------- |
| HTML5_parser          | HTML parsing and DOM construction |
| CSS_layout            | Style computation and layout      |
| JS_engine             | SpiderMonkey JavaScript engine    |
| SVG_renderer          | SVG rendering pipeline            |
| Canvas_WebGL          | Canvas 2D and WebGL contexts      |
| Web_Audio             | Web Audio API processing          |
| WebRTC                | Real-time communication APIs      |
| DOM_events            | Event handling and dispatch       |
| IndexedDB             | Client-side database              |
| WebAssembly           | Wasm compilation and execution    |
| CSS_animations        | CSS transitions and animations    |
| Shadow_DOM            | Shadow DOM and web components     |
| Intersection_Observer | Intersection Observer API         |
| Service_Worker        | Service Worker lifecycle          |
| WebSockets            | WebSocket connections             |

## Troubleshooting

### API connectivity fails on startup

```
FAILED: http://your-endpoint/health → <error>
The proxy is not reachable. Fix your ANTHROPIC_BASE_URL in .env
```

Verify your `ANTHROPIC_BASE_URL` in `.env` is correct and the endpoint is reachable.

### Firefox not found

Set `firefox_path` in `config.json` to the full path of your Firefox binary. On Windows, use forward slashes: `C:/Program Files/Mozilla Firefox/firefox.exe`.

### Firefox fails to start (missing libraries)

On headless Linux servers, install required dependencies:

```bash
sudo apt install libgtk-3-0 libdbus-glib-1-2 libasound2 libx11-xcb1 libxt6 xvfb
```

### No DISPLAY environment variable

Start Xvfb and set the display:

```bash
Xvfb :99 &
export DISPLAY=:99
```

The fuzzer handles this automatically when `use_xvfb: true` in `config.json`.

### No crashes detected

- Use an **ASan build** of Firefox (`pip install fuzzfetch && fuzzfetch --asan -o ~/firefox-asan`)
- Lower `novelty_threshold` (e.g., `0.75`) to allow more test case variations
- Increase `workers` for higher throughput
- Decrease `delay_between_tests` if your API rate limit allows

### Dashboard not loading

Make sure the API server (`python api.py`) is running before starting the dashboard. The dashboard proxies requests to `http://localhost:6767`.

### High memory usage

- Reduce `novelty_max_corpus` to limit the TF-IDF corpus size
- Reduce `workers` count
- The fuzzer automatically kills stale Firefox processes, but you can manually clean up with `taskkill /F /IM firefox.exe` (Windows) or `pkill firefox` (Linux/macOS)

## License

This project is intended for authorized security research and testing only. Use responsibly and only against software you have permission to test.
