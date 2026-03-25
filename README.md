# Blackbox Protocol

**AI-powered Firefox fuzzer that generates surgical, CVE-quality test cases.**

Blackbox uses Claude as a red-team security researcher to craft HTML/JS exploits targeting memory corruption bugs. It's the execution layer of a two-part autonomous vulnerability hunting pipeline — paired with [Redbox Protocol](https://github.com/chairulridjaal/redbox-protocol), which reads actual Firefox C++ source code to guide the attack.

> ⚠️ **Honest disclaimer:** After 400+ test cases and 500+ research sessions, we haven't found a crash yet. Firefox is *really* well-fuzzed. But the infrastructure is solid, the approach is sound, and we're still hunting.

---

## The Dream vs Reality

**What we built:**
- Claude generates exploit test cases modeled on real CVEs
- Reads actual Firefox C++ source to find targets
- Multi-armed bandit strategy selection (UCB1)
- Learns across sessions with persistent knowledge store
- Real-time dashboard, crash triage, Bugzilla-ready reports

**What happened:**
- 392 briefs tested → 0 crashes
- Turns out all the CVE variants are already patched
- Mozilla's fuzzing infrastructure is elite-tier
- We pivoted to targeting recent commits instead

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    REDBOX PROTOCOL                          │
│        (reads Firefox C++ → generates attack briefs)        │
└─────────────────────────┬───────────────────────────────────┘
                          │ briefs/*.json
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    BLACKBOX PROTOCOL                        │
│                                                             │
│   Claude ──→ HTML/JS ──→ Firefox ASAN ──→ Crash Triage     │
│     ↑                                           │           │
│     └──── feedback loop (learn from results) ───┘           │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

- **Brief-Guided Targeting** — Consumes attack briefs from Redbox with specific C++ classes, methods, and trigger sequences
- **11 Attack Strategies** — UAF, type confusion, JIT exploits, integer overflow, WASM boundaries, and more
- **UCB1 Strategy Selection** — Multi-armed bandit balances exploration vs exploitation
- **Semantic Novelty Detection** — TF-IDF deduplication prevents testing the same thing twice
- **Differential Testing** — Runs on both Firefox Nightly AND ESR to catch backport gaps
- **ASAN Hardened** — 64MB quarantine, 512-byte redzones, stack UAF detection
- **Auto Crash Triage** — Parses ASAN scariness scores, rates exploitability 1-5
- **Crash Minimization** — Claude reduces crashes to minimal reproducers
- **Web Dashboard** — React UI for crash management and stats

---

## Quick Start

```bash
# Clone
git clone https://github.com/chairulridjaal/blackbox-protocol
cd blackbox-protocol

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env  # Add your ANTHROPIC_API_KEY

# Download Firefox ASAN build
./setup-firefox.sh

# Run
python main.py
```

Dashboard at `http://localhost:6868`

---

## Strategies

| Strategy | Target | Status |
|----------|--------|--------|
| `use_after_free` | Raw pointers across callbacks | Testing |
| `type_confusion` | Polymorphic dispatch bugs | Testing |
| `jit_range_analysis` | SpiderMonkey range inference | Testing |
| `integer_overflow` | Graphics/layout math | **New focus** |
| `wasm_type_boundary` | WASM ↔ JS transitions | Testing |
| `buffer_detach` | ArrayBuffer neutering | Testing |
| `gc_pressure` | GC timing attacks | Testing |
| `layout_uaf` | Layout frame lifecycle | Testing |
| `animation_lifecycle` | Animation timing | Testing |
| `iframe_lifecycle` | Frame destruction races | Testing |
| `xslt_xpath` | XSLT transform bugs | Testing |

---

## Results So Far

```
Sessions:     500+
Briefs:       392 tested
Crashes:      0 (Firefox is tough)
Findings:     344 code observations
Hypotheses:   433 vulnerability candidates
```

We learned a lot about Firefox internals. The knowledge base is valuable even without crashes.

---

## Lessons Learned

1. **CVE variant analysis doesn't work** — Those bugs are patched everywhere
2. **Firefox fuzzing is mature** — OSS-Fuzz, libFuzzer, they've seen it all
3. **Target recent code** — New commits haven't been fuzzed yet
4. **Logic bugs > memory bugs** — CORS, same-origin, privilege escalation might be less fuzzer-covered

---

## Project Structure

```
blackbox-protocol/
├── main.py              # Orchestrator
├── worker.py            # Fuzzing worker loop
├── modules/
│   ├── generator.py     # Claude test generation
│   ├── browser.py       # Firefox ASAN runner
│   ├── crash_handler.py # Triage + minimize
│   ├── novelty.py       # TF-IDF deduplication
│   └── strategies.py    # UCB1 selection
├── dashboard/           # React frontend
├── crashes/             # Crash artifacts
└── config.json          # Settings
```

---

## Related

- **[Redbox Protocol](https://github.com/chairulridjaal/redbox-protocol)** — The research agent that reads Firefox source
- **[Google Big Sleep](https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html)** — Inspiration for the approach

---

## License

Research purposes only.
---

*Great way to spend your tokens, lol.*
