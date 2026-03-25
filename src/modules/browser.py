import subprocess
import time
import os
import platform
import signal
import tempfile
import shutil


def kill_stale_processes(pid=None):
    """Kill Firefox processes — scoped to PID if given, global cleanup otherwise."""
    system = platform.system()
    try:
        if pid is not None:
            if system == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid), "/T"],
                    capture_output=True, timeout=5
                )
            else:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        else:
            if system == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/IM", "firefox.exe", "/T"],
                    capture_output=True, timeout=5
                )
            else:
                subprocess.run(
                    ["pkill", "-9", "firefox"],
                    capture_output=True, timeout=5
                )
    except Exception:
        pass
    time.sleep(0.5)


def create_temp_profile():
    """Create a temporary Firefox profile directory."""
    return tempfile.mkdtemp(prefix="firefox_fuzz_")


def cleanup_profile(profile_dir):
    """Clean up temporary profile directory."""
    try:
        shutil.rmtree(profile_dir, ignore_errors=True)
    except Exception:
        pass


def launch_firefox(firefox_path, html_path, profile_dir, timeout=15, display=None, extra_env=None):
    """Launch Firefox with isolated profile and return execution result.

    Args:
        extra_env: Optional dict of additional environment variables (e.g. JS_GC_ZEAL).
    """

    if platform.system() == "Windows":
        html_path = "file:///" + html_path.replace("\\", "/")

    cmd = [
        firefox_path,
        "--no-remote",
        "--profile", profile_dir,
        "--screenshot", "/dev/null",
        html_path
    ]
    if not display:
        cmd.insert(1, "--headless")

    env = os.environ.copy()
    if display:
        env["DISPLAY"] = display

    # ── Sanitizer configuration ───────────────────────────────────────────
    # quarantine_size_mb=64: delays memory reuse → catches UAFs that fire
    #   later (default 256KB is too small — freed slots get reused instantly)
    # redzone=512: larger guard zones around allocations → catches small OOB
    # malloc_fill_byte=0xbe / free_fill_byte=0xce: deterministic fill so
    #   uninit reads and UAF reads produce recognizable bad data
    # detect_stack_use_after_return=1: catches stack UAF via fake frames
    # print_scariness=1: ASAN rates crash exploitability (0-100 score)
    # malloc_context_size=30: deeper stack traces in reports
    env["ASAN_OPTIONS"] = (
        "abort_on_error=1:"
        "detect_leaks=0:"
        "allocator_may_return_null=1:"
        "log_path=stderr:"
        "quarantine_size_mb=64:"
        "redzone=512:"
        "malloc_fill_byte=190:"
        "free_fill_byte=206:"
        "detect_stack_use_after_return=1:"
        "print_scariness=1:"
        "malloc_context_size=30:"
        "detect_container_overflow=1:"
        "strict_string_checks=1:"
        "check_initialization_order=1"
    )
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    env["TSAN_OPTIONS"] = "report_bugs=1"
    env["LSAN_OPTIONS"] = "detect_leaks=0"

    # ── Firefox-specific debug signals ────────────────────────────────────
    # XPCOM_DEBUG_BREAK=stack-and-abort: makes NS_ASSERTION fatal →
    #   surfaces contract violations that normally just print warnings
    # MOZ_CRASHREPORTER_DISABLE: prevents crash dialog from blocking
    env["XPCOM_DEBUG_BREAK"] = "stack-and-abort"
    env["MOZ_CRASHREPORTER_DISABLE"] = "1"
    env["MOZ_GDB_SLEEP"] = "0"

    # Extra env vars from caller (e.g. JS_GC_ZEAL for verification tests)
    if extra_env:
        env.update(extra_env)

    system = platform.system()
    preexec = None
    if system != "Windows":
        preexec = os.setsid

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            preexec_fn=preexec
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            output = stdout + stderr
            return {
                "exit_code": proc.returncode,
                "output": output,
                "timed_out": False,
                "pid": proc.pid,
                "error": None
            }
        except subprocess.TimeoutExpired:
            kill_stale_processes(pid=proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            output = (stdout or "") + (stderr or "")
            return {
                "exit_code": -1,
                "output": output,
                "timed_out": True,
                "pid": proc.pid,
                "error": "Process timed out"
            }
    except Exception as e:
        return {
            "exit_code": -1,
            "output": "",
            "timed_out": False,
            "pid": None,
            "error": str(e)
        }
