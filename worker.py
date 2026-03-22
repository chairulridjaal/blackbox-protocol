import os
import time
from anthropic import Anthropic
from modules.browser import launch_firefox, create_temp_profile, cleanup_profile
from modules.generator import select_strategy, record_result, generate_test_case
from modules.novelty import NoveltyTracker
from modules.subsystem_tracker import SubsystemTracker
from modules.crash_handler import detect_issue, CrashDeduplicator, minimize_test_case, generate_report
from modules.plateau_detector import PlateauDetector
from modules.storage import save_crash
from utils.html_utils import extract_html

MAX_HISTORY_TURNS = 6


def worker_loop(worker_id, config, shared_dedup=None):
    """Main fuzzing loop for a single worker."""
    client = Anthropic(
        api_key=config["api_key"],
        base_url=config["base_url"],
        timeout=600.0,
        max_retries=3,
    )

    tracker = SubsystemTracker()
    novelty_tracker = NoveltyTracker(
        threshold=config.get("novelty_threshold", 0.85),
        max_corpus=config.get("novelty_max_corpus", 500)
    )
    plateau_detector = PlateauDetector(
        window=config.get("plateau_window", 20),
        threshold=config.get("plateau_threshold", 0.05)
    )
    deduplicator = shared_dedup or CrashDeduplicator()

    history = [
        {"role": "user", "content": "I need you to generate browser fuzzing test cases for Firefox. Start with something that targets the HTML5 parser with malformed nested structures."},
    ]

    test_count = 0
    novelty_skips = 0
    display = config.get("xvfb_display", ":99") if config.get("use_xvfb", False) else None

    print(f"[Worker {worker_id}] Starting...")

    while True:
        test_count += 1
        profile_dir = create_temp_profile()

        try:
            # 1. Select strategy via UCB1
            strategy_name, strategy_prompt = select_strategy()

            # 2. Get underexplored subsystems
            subsystem_hint = tracker.get_underexplored(
                top_n=config.get("subsystem_underexplored_top_n", 3)
            )

            # 3. Build context prompt
            context_str = tracker.build_context_prompt()

            # 4. Check for plateau
            plateau_prompt = None
            is_plateau = plateau_detector.is_plateau()
            if is_plateau:
                plateau_prompt = plateau_detector.get_plateau_prompt()
                print(f"[Worker {worker_id}] Plateau detected! Injecting diversity prompt...")

            # Build combined prompt with context and plateau if needed
            combined_prompt = strategy_prompt
            if plateau_prompt:
                combined_prompt = plateau_prompt + "\n\n" + combined_prompt

            # 5. Generate test case
            history, html_content = generate_test_case(
                client, history, strategy_name, combined_prompt, subsystem_hint
            )

            # 6. Extract HTML (already done in generate_test_case, but ensure clean)
            html_content = extract_html(html_content)

            # 7. Novelty check
            is_novel, score = novelty_tracker.is_novel(html_content)

            # Determine subsystem for this test
            current_subsystem = subsystem_hint[0] if subsystem_hint else "HTML5_parser"

            # 8. Skip if not novel
            if not is_novel:
                novelty_skips += 1
                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → SKIPPED (duplicate)")
                history.append({"role": "user", "content": "That test case was too similar to previous ones. Generate something COMPLETELY DIFFERENT targeting a new subsystem with a novel approach."})
                record_result(strategy_name, found_crash=False)
                plateau_detector.update(False)
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

            # 12. Update plateau detector
            plateau_detector.update(True)

            # 13. Record test for subsystem
            tracker.record_test(current_subsystem)

            # 14. Handle issue
            if is_issue:
                # 14a. Deduplication check
                is_dup, signature = deduplicator.is_duplicate(run_result["output"], issue_reason, config["crashes_dir"])
                if is_dup:
                    print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → DUP (sig:{signature[:8]})")
                    record_result(strategy_name, found_crash=False)
                    continue

                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f}] → CRASH sev:{severity} sig:{signature[:8]}")

                try:
                    # 14b. Minimize
                    minimized = minimize_test_case(client, html_content, issue_reason, run_result["output"])

                    # 14c. Generate report
                    report = generate_report(client, html_content, minimized, issue_reason, run_result["output"], severity)

                    # 14d. Save crash
                    crash_id, html_path, report_path = save_crash(
                        minimized, report, html_content, run_result["output"],
                        issue_reason, severity, signature, strategy_name,
                        current_subsystem, worker_id, test_count,
                        config["crashes_dir"], novelty_skips
                    )

                    print(f"  Crash ID: {crash_id}")
                    print(f"  Files saved to {config['crashes_dir']}/")

                    # 14e. Record crash for strategy
                    record_result(strategy_name, found_crash=True)

                    # 14f. Record crash for subsystem
                    tracker.record_crash(current_subsystem)

                    # 14g. Inject success feedback
                    history.append({
                        "role": "user",
                        "content": f"Excellent! That last test case triggered a {issue_reason} (severity {severity}/5). Generate an aggressive VARIANT that might trigger something similar or worse. Mutate it aggressively."
                    })

                except Exception as e:
                    print(f"  Error during crash analysis: {e}")
                    record_result(strategy_name, found_crash=True)
            else:
                # 15. No issue found
                print(f"[W{worker_id} | T#{test_count} | strategy:{strategy_name} | subsystem:{current_subsystem} | novelty:{score:.2f} | plateau:{is_plateau}] → OK")
                record_result(strategy_name, found_crash=False)

            # 16. History trimming — keep first message + most recent turns
            if len(history) > MAX_HISTORY_TURNS * 2:
                history = history[:1] + history[-(MAX_HISTORY_TURNS * 2 - 1):]

        except Exception as e:
            import traceback
            print(f"[Worker {worker_id}] Error in test #{test_count}: {e}")
            traceback.print_exc()

        finally:
            cleanup_profile(profile_dir)

        # 17. Delay between tests
        time.sleep(config["delay_between_tests"])
