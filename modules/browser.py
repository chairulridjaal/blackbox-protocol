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


def launch_firefox(firefox_path, html_path, profile_dir, timeout=15, display=None):
    """Launch Firefox with isolated profile and return execution result."""

    if platform.system() == "Windows":
        html_path = "file:///" + html_path.replace("\\", "/")

    cmd = [
        firefox_path,
        "--headless",
        "--no-remote",
        "--profile", profile_dir,
        "--disable-gpu",
        html_path
    ]

    env = os.environ.copy()
    if display:
        env["DISPLAY"] = display

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
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            return {
                "exit_code": -1,
                "output": "",
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
