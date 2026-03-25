import os
import json
import time
import random
from anthropic import Anthropic
from src.modules.browser import launch_firefox, create_temp_profile, cleanup_profile
from src.modules.generator import select_strategy, record_result, generate_test_case
from src.modules.novelty import NoveltyTracker
from src.modules.subsystem_tracker import SubsystemTracker
from src.modules.crash_handler import detect_issue, CrashDeduplicator, minimize_test_case, generate_report
from src.modules.plateau_detector import PlateauDetector
from src.modules.storage import save_crash
from utils.html_utils import extract_html


# ── Redbox Protocol Integration (Attack Brief Consumption) ───────────

def consume_attack_brief(briefs_dir):
    """Consume the oldest pending attack brief from the briefs directory.

    Atomically renames to .processing to prevent other workers from picking it up.
    Returns parsed brief dict or None.
    """
    if not briefs_dir or not os.path.isdir(briefs_dir):
        return None

    try:
        files = sorted(
            [f for f in os.listdir(briefs_dir) if f.endswith(".json")],
            key=lambda f: f  # Sort by filename (timestamp-prefixed)
        )
    except OSError:
        return None

    for fname in files:
        fpath = os.path.join(briefs_dir, fname)
        processing_path = fpath + ".processing"

        try:
            # Atomic rename to claim the brief
            os.rename(fpath, processing_path)

            with open(processing_path, "r") as f:
                brief = json.load(f)

            brief["_processing_path"] = processing_path
            return brief

        except (FileNotFoundError, OSError):
            # Another worker got it first — try next one
            continue
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[brief] Error parsing {fname}: {e}")
            # Move bad file aside
            try:
                os.rename(processing_path, fpath + ".error")
            except OSError:
                pass
            continue

    return None


def build_brief_prompt(brief):
    """Build a test generation prompt from an attack brief.

    Injects the research findings as high-priority context for the LLM.
    """
    target = brief.get("target", {})
    vuln = brief.get("vulnerability", {})
    trigger = brief.get("trigger", {})

    parts = [
        "## ATTACK BRIEF FROM RESEARCH PIPELINE",
        f"**Priority:** {brief.get('priority', 'medium')}",
        f"**Confidence:** {brief.get('confidence', 'medium')}",
        "",
        f"### Target",
        f"- C++ Class: `{target.get('class', 'unknown')}`",
        f"- Method: `{target.get('method', 'unknown')}`",
        f"- Source file: `{target.get('file', 'unknown')}`",
        "",
        f"### Vulnerability Hypothesis",
        f"- Class: {vuln.get('class', 'unknown')}",
        f"- Hypothesis: {vuln.get('hypothesis', 'No hypothesis provided')}",
    ]

    if vuln.get("source_evidence"):
        parts.extend([
            "",
            "### C++ Source Evidence",
            f"```cpp",
            vuln["source_evidence"],
            "```",
        ])

    if vuln.get("related_cve"):
        parts.append(f"\n**Related CVE:** {vuln['related_cve']}")

    if trigger.get("sequence"):
        parts.extend([
            "",
            "### Suggested Trigger Sequence",
            trigger["sequence"],
        ])

    parts.extend([
        "",
        "Generate a surgical HTML/JS test case that targets this EXACT vulnerability. "
        "Use the source evidence above to craft the precise API call sequence needed. "
        "This is research-guided — be precise, not random.",
    ])

    return "\n".join(parts)


def write_feedback(brief_id, feedback_data, feedback_dir):
    """Write feedback about a brief's test result for the research pipeline."""
    if not feedback_dir:
        return

    os.makedirs(feedback_dir, exist_ok=True)
    feedback_data["brief_id"] = brief_id
    feedback_data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    fpath = os.path.join(feedback_dir, f"{brief_id}_feedback.json")
    try:
        with open(fpath, "w") as f:
            json.dump(feedback_data, f, indent=2)
    except Exception as e:
        print(f"[brief] Error writing feedback: {e}")


def finalize_brief(brief, success=False):
    """Clean up a processed brief file."""
    processing_path = brief.get("_processing_path")
    if not processing_path or not os.path.exists(processing_path):
        return

    try:
        # Move to processed subdirectory
        briefs_dir = os.path.dirname(processing_path)
        processed_dir = os.path.join(briefs_dir, "processed")
        os.makedirs(processed_dir, exist_ok=True)
        fname = os.path.basename(processing_path).replace(".processing", "")
        os.rename(processing_path, os.path.join(processed_dir, fname))
    except OSError:
        pass


def worker_loop(worker_id, config, shared_dedup=None, firefox_version="unknown", shared_tracker=None, shared_novelty=None):
    """Main fuzzing loop for a single worker."""
    client = Anthropic(
        api_key=config["api_key"],
        base_url=config["base_url"],
        timeout=600.0,
        max_retries=3,
    )

    tracker = shared_tracker or SubsystemTracker()
    novelty_tracker = shared_novelty or NoveltyTracker(
        threshold=config.get("novelty_threshold", 0.85),
        max_corpus=config.get("novelty_max_corpus", 500)
    )
    plateau_detector = PlateauDetector(
        window=config.get("plateau_window", 20),
        threshold=config.get("plateau_threshold", 0.05)
    )
    deduplicator = shared_dedup or CrashDeduplicator()
    max_history_turns = config.get("history_max_turns", 6)

    # Diversify initial prompt per worker to avoid correlated first tests
    _initial_prompts = [
        "Generate a browser fuzzing test case for Firefox targeting DOM node lifecycle and use-after-free via MutationObserver re-entrancy.",
        "Generate a browser fuzzing test case for Firefox targeting SpiderMonkey JIT type confusion via shape transitions in hot loops.",
        "Generate a browser fuzzing test case for Firefox targeting CSS layout frame destruction during ResizeObserver callbacks.",
        "Generate a browser fuzzing test case for Firefox targeting Web Animations API timeline iteration with concurrent element removal.",
        "Generate a browser fuzzing test case for Firefox targeting XSLT/XPath node tree manipulation during stylesheet transformation.",
        "Generate a browser fuzzing test case for Firefox targeting ArrayBuffer detachment during TypedArray iteration via postMessage transfer.",
        "Generate a browser fuzzing test case for Firefox targeting WebAssembly type boundary confusion with GC proposal types.",
        "Generate a browser fuzzing test case for Firefox targeting iframe document lifecycle with cross-document node adoption.",
    ]
    history = [
        {"role": "user", "content": _initial_prompts[(worker_id - 1) % len(_initial_prompts)]},
    ]

    test_count = 0
    novelty_skips = 0
    display = config.get("xvfb_display", ":99") if config.get("use_xvfb", False) else None

    print(f"[Worker {worker_id}] Starting...")

    # Redbox protocol brief consumption config
    briefs_dir = config.get("briefs_dir")
    feedback_dir = config.get("feedback_dir")

    while True:
        test_count += 1
        profile_dir = create_temp_profile()
        active_brief = None  # Track if this test was brief-guided

        try:
            # 0. Check for attack briefs from Redbox research pipeline
            #    Brief-guided tests get priority — they're research-backed
            active_brief = consume_attack_brief(briefs_dir)

            # 1. Select strategy via UCB1
            strategy_name, strategy_prompt = select_strategy()

            # 2. Get underexplored subsystems — offset by worker_id so workers
            #    target DIFFERENT subsystems instead of all picking the same one
            all_underexplored = tracker.get_underexplored(
                top_n=max(config.get("subsystem_underexplored_top_n", 3) + 4, 8)
            )
            # Each worker picks from a different offset in the list
            worker_offset = (worker_id - 1) % max(len(all_underexplored), 1)
            subsystem_hint = all_underexplored[worker_offset:worker_offset+3]
            if len(subsystem_hint) < 3:
                subsystem_hint += all_underexplored[:3 - len(subsystem_hint)]

            # 3. Build context prompt
            context_str = tracker.build_context_prompt()

            # 4. Check for plateau — on plateau, RESET history to break the rut
            plateau_prompt = None
            is_plateau = plateau_detector.is_plateau()
            if is_plateau:
                plateau_prompt = plateau_detector.get_plateau_prompt()
                print(f"[Worker {worker_id}] Plateau detected! Resetting history + injecting diversity prompt...")
                # Reset history to just the initial prompt — the bloated context IS the problem
                history = [history[0]]

            # Build combined prompt with subsystem requirement FIRST
            subsystem_target = subsystem_hint[0] if subsystem_hint else "JS_engine"

            # If we have an attack brief from Redbox, it takes priority
            if active_brief:
                brief_prompt = build_brief_prompt(active_brief)
                combined_prompt = brief_prompt + "\n\n" + strategy_prompt
                subsystem_target = active_brief.get("target", {}).get("class", subsystem_target)
                print(f"[W{worker_id} | T#{test_count}] Using attack brief: {active_brief.get('brief_id', '?')}")
            elif is_plateau and len(subsystem_hint) > 1:
                # On plateau, skip the top pick (likely exhausted) and use next candidate
                subsystem_target = subsystem_hint[1]
                current_subsystem = subsystem_target
                combined_prompt = (
                    plateau_prompt + "\n\n"
                    + context_str + "\n\n"
                    + f"Switch to testing the {subsystem_target} subsystem with a completely new technique.\n\n"
                    + strategy_prompt
                )
            else:
                subsystem_instruction = f"REQUIRED: Your test case MUST target the {subsystem_target} subsystem specifically."
                if subsystem_target != "HTML5_parser":
                    subsystem_instruction += " Do not generate an HTML parser test."
                combined_prompt = (
                    subsystem_instruction + "\n\n"
                    + context_str + "\n\n"
                    + strategy_prompt
                )
                if plateau_prompt:
                    combined_prompt = plateau_prompt + "\n\n" + combined_prompt

            # 5. Generate test case
            history, html_content = generate_test_case(
                client, history, strategy_name, combined_prompt, subsystem_hint
            )

            # 6. HTML is already extracted by generate_test_case — no double extraction
            # (double extract_html could strip content if HTML contains backtick sequences)

            # 7. Novelty check
            is_novel, score = novelty_tracker.is_novel(html_content)

            # Determine subsystem for this test
            current_subsystem = subsystem_hint[0] if subsystem_hint else "HTML5_parser"

            # 8. Skip if not novel
            if not is_novel:
                novelty_skips += 1
                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → SKIPPED (duplicate)")
                # Vary the retry message to avoid repetitive history
                _skip_msgs = [
                    "That test was too similar. Target a COMPLETELY different Firefox subsystem and C++ code path.",
                    "Too similar — try a radically different approach. Use different DOM APIs, different timing, different memory patterns.",
                    "Duplicate detected. Switch to a new attack surface entirely — different subsystem, different vulnerability class.",
                    "That pattern is exhausted. Think of a novel invariant violation that hasn't been tried yet.",
                ]
                history.append({"role": "user", "content": random.choice(_skip_msgs)})
                record_result(strategy_name, found_crash=False)
                tracker.record_test(current_subsystem)
                plateau_detector.update(False)
                # Trim history BEFORE continuing (prevents unbounded growth on consecutive skips)
                if len(history) > max_history_turns * 2:
                    history = history[:1] + history[-(max_history_turns * 2 - 1):]
                continue

            # 9. Save HTML to temp file
            test_file = os.path.join(profile_dir, f"test_{worker_id}_{test_count}.html")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            # 10. Launch Firefox
            run_result = launch_firefox(
                config["firefox_path"], test_file, profile_dir,
                config["timeout_seconds"], display
            )

            # 11. Detect issues
            is_issue, issue_reason, severity = detect_issue(run_result, config)

            # 13. Record test for subsystem
            tracker.record_test(current_subsystem)

            # 14. Handle issue
            if is_issue:
                # 14a. Skip low-severity findings (timeouts, minor errors)
                min_severity = config.get("min_save_severity", 3)
                if severity < min_severity:
                    print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → {issue_reason} sev:{severity} (below threshold {min_severity}, skipped)")
                    record_result(strategy_name, found_crash=False)
                    plateau_detector.update(False)
                    if len(history) > max_history_turns * 2:
                        history = history[:1] + history[-(max_history_turns * 2 - 1):]
                    continue

                # 14b. Deduplication check
                is_dup, signature = deduplicator.is_duplicate(run_result["output"], issue_reason, config["crashes_dir"])
                if is_dup:
                    print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → DUP (sig:{signature[:8]})")
                    record_result(strategy_name, found_crash=False)
                    if len(history) > max_history_turns * 2:
                        history = history[:1] + history[-(max_history_turns * 2 - 1):]
                    continue

                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → CRASH sev:{severity} sig:{signature[:8]}")

                try:
                    # 14c. Minimize
                    minimized = minimize_test_case(client, html_content, issue_reason, run_result["output"])

                    # 14d. Generate report
                    report = generate_report(client, html_content, minimized, issue_reason, run_result["output"], severity)

                    # 14e. Save crash
                    crash_id, html_path, report_path = save_crash(
                        minimized, report, html_content, run_result["output"],
                        issue_reason, severity, signature, strategy_name,
                        current_subsystem, worker_id, test_count,
                        config["crashes_dir"], novelty_skips, firefox_version
                    )

                    print(f"  Crash ID: {crash_id}")
                    print(f"  Files saved to {config['crashes_dir']}/")

                    # 14f. Record crash for strategy
                    record_result(strategy_name, found_crash=True)

                    # 14g. Record crash for subsystem
                    tracker.record_crash(current_subsystem)

                    # 14h. Inject success feedback
                    history.append({
                        "role": "user",
                        "content": f"Excellent! That last test case triggered a {issue_reason} (severity {severity}/5). Generate an aggressive VARIANT that might trigger something similar or worse. Mutate it aggressively."
                    })

                    # 14i. Write feedback to Redbox if this was a brief-guided test
                    if active_brief:
                        write_feedback(active_brief["brief_id"], {
                            "crash_id": crash_id,
                            "severity": severity,
                            "asan_output": run_result["output"][:2000],
                            "result": "crash",
                        }, feedback_dir)

                except Exception as e:
                    print(f"  Error during crash analysis: {e}")
                    record_result(strategy_name, found_crash=True)
                plateau_detector.update(True)
            else:
                # 15. No issue found on Nightly
                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f} | plateau:{is_plateau}] → OK (Nightly)")

                # 15a. Differential testing: try ESR if configured
                esr_path = config.get("firefox_esr_path")
                if config.get("differential_testing") and esr_path and os.path.exists(esr_path):
                    esr_result = launch_firefox(
                        esr_path, test_file, profile_dir,
                        config["timeout_seconds"], display
                    )
                    esr_issue, esr_reason, esr_severity = detect_issue(esr_result, config)

                    if esr_issue and esr_severity >= config.get("min_save_severity", 2):
                        # Found something! Crashes ESR but not Nightly = patched bug
                        is_dup, signature = deduplicator.is_duplicate(esr_result["output"], esr_reason, config["crashes_dir"])
                        if not is_dup:
                            print(f"[W{worker_id} | T#{test_count}] → DIFFERENTIAL CRASH! ESR sev:{esr_severity} sig:{signature[:8]} (patched in Nightly)")
                            try:
                                minimized = minimize_test_case(client, html_content, esr_reason, esr_result["output"])
                                report = generate_report(client, html_content, minimized, esr_reason, esr_result["output"], esr_severity)
                                # Mark as differential crash in report
                                report = f"[DIFFERENTIAL - Patched in Nightly {firefox_version}]\n\n" + report
                                crash_id, html_path, report_path = save_crash(
                                    minimized, report, html_content, esr_result["output"],
                                    f"[DIFF] {esr_reason}", esr_severity, signature, strategy_name,
                                    current_subsystem, worker_id, test_count,
                                    config["crashes_dir"], novelty_skips, f"ESR (diff vs {firefox_version})"
                                )
                                print(f"  Differential crash saved: {crash_id}")
                                record_result(strategy_name, found_crash=True)
                                tracker.record_crash(current_subsystem)
                                plateau_detector.update(True)
                                if active_brief:
                                    write_feedback(active_brief["brief_id"], {
                                        "crash_id": crash_id,
                                        "severity": esr_severity,
                                        "asan_output": esr_result["output"][:2000],
                                        "result": "differential_crash",
                                    }, feedback_dir)
                                # Skip normal "no crash" path
                                if len(history) > max_history_turns * 2:
                                    history = history[:1] + history[-(max_history_turns * 2 - 1):]
                                if active_brief:
                                    finalize_brief(active_brief, success=True)
                                continue
                            except Exception as e:
                                print(f"  Error analyzing ESR crash: {e}")
                        else:
                            print(f"[W{worker_id} | T#{test_count}] → ESR crash DUP (sig:{signature[:8]})")
                    else:
                        print(f"[W{worker_id} | T#{test_count}] → ESR OK")

                record_result(strategy_name, found_crash=False)
                plateau_detector.update(True)

            # 16. History trimming — keep first message + most recent turns
            if len(history) > max_history_turns * 2:
                history = history[:1] + history[-(max_history_turns * 2 - 1):]

            # 17. Finalize brief if this was a brief-guided test
            if active_brief:
                if not is_issue:
                    write_feedback(active_brief["brief_id"], {
                        "result": "no_crash",
                        "severity": 0,
                    }, feedback_dir)
                finalize_brief(active_brief, success=is_issue)

        except Exception as e:
            import traceback
            print(f"[Worker {worker_id}] Error in test #{test_count}: {e}")
            traceback.print_exc()

        finally:
            cleanup_profile(profile_dir)

        # 17. Delay between tests
        time.sleep(config["delay_between_tests"])
