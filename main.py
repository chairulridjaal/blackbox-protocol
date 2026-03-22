import os
import sys
import json
import signal
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.browser import kill_stale_processes
from worker import worker_loop


def load_config():
    """Load config with defaults for new keys, secrets from .env."""
    load_dotenv(override=True)

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)

    # Override secrets from environment variables
    config["api_key"] = os.environ.get("ANTHROPIC_API_KEY", config.get("api_key", ""))
    config["base_url"] = os.environ.get("ANTHROPIC_BASE_URL", config.get("base_url", ""))

    defaults = {
        "asan_keywords": [
            "AddressSanitizer", "use-after-free", "heap-buffer-overflow",
            "stack-buffer-overflow", "SEGV", "heap corruption"
        ],
        "novelty_threshold": 0.85,
        "novelty_max_corpus": 500,
        "plateau_window": 20,
        "plateau_threshold": 0.05,
        "subsystem_underexplored_top_n": 3,
        "history_max_turns": 20,
        "xvfb_display": ":99",
        "use_xvfb": False,
    }
    for key, default_value in defaults.items():
        config.setdefault(key, default_value)

    return config


def main():
    """Entry point — load config, clean up, and spawn workers."""
    config = load_config()

    print("=" * 60)
    print("FIREFOX FUZZER - Modular Edition")
    print("=" * 60)
    print(f"Workers: {config['workers']}")
    print(f"Crashes dir: {os.path.abspath(config['crashes_dir'])}")
    print(f"Dashboard: http://localhost:{config.get('dashboard_port', 5173)}")
    print(f"Novelty threshold: {config.get('novelty_threshold', 0.85)}")
    print(f"Plateau window: {config.get('plateau_window', 20)}")
    print(f"API base URL: {config['base_url']}")
    print(f"API key: {config['api_key'][:12]}...")
    print("=" * 60)

    # Pre-flight connectivity check
    print("\nTesting API connectivity...")
    import urllib.request, urllib.error
    health_url = config["base_url"].rstrip("/") + "/health"
    try:
        req = urllib.request.urlopen(health_url, timeout=10)
        print(f"  {health_url} → {req.status} OK")
    except Exception as e:
        print(f"  FAILED: {health_url} → {e}")
        print(f"  The proxy is not reachable. Fix your ANTHROPIC_BASE_URL in .env")
        sys.exit(1)

    print("Press Ctrl+C to stop\n")

    print("Cleaning up any existing Firefox processes...")
    kill_stale_processes()

    os.makedirs(config["crashes_dir"], exist_ok=True)

    if config.get("auto_open_dashboard"):
        print(f"\nStart dashboard in another terminal.\n")

    from modules.crash_handler import CrashDeduplicator
    shared_dedup = CrashDeduplicator()

    if config["workers"] == 1:
        worker_loop(1, config, shared_dedup)
    else:
        with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
            futures = [executor.submit(worker_loop, i + 1, config, shared_dedup) for i in range(config["workers"])]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                print("\n\nShutting down workers...")
                executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nFuzzer stopped by user.")
        kill_stale_processes()
