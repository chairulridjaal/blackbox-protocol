import hashlib
import re
import os
import glob
import json
from utils.html_utils import extract_html

ANALYSIS_MODEL = "claude-opus-4.5"


DEFAULT_ASAN_KEYWORDS = [
    "AddressSanitizer", "use-after-free", "heap-buffer-overflow",
    "stack-buffer-overflow", "SEGV", "heap corruption"
]

# Firefox-specific assertion patterns (separate from ASAN)
MOZ_ASSERT_KEYWORDS = [
    "MOZ_CRASH", "MOZ_RELEASE_ASSERT", "MOZ_ASSERT",
    "MOZ_DIAGNOSTIC_ASSERT", "NS_ASSERTION"
]


def _parse_scariness(output: str) -> int:
    """Parse ASAN Scariness score from output (0-100). Returns 0 if not found."""
    match = re.search(r'Scariness:\s*(\d+)', output)
    return int(match.group(1)) if match else 0


def _boost_severity_from_crash_type(output: str, base_severity: int) -> int:
    """Boost severity based on exploitability signals in crash output."""
    output_lower = output.lower()
    # WRITE bugs are almost always exploitable
    if any(w in output_lower for w in ["write", "double-free", "double free"]):
        return max(base_severity, 5)
    # UAF and type confusion are high value
    if any(w in output_lower for w in ["use-after-free", "type confusion",
                                        "heap-buffer-overflow"]):
        return max(base_severity, 5)
    # Stack overflow write = ROP
    if "stack-buffer-overflow" in output_lower and "write" in output_lower:
        return max(base_severity, 5)
    # MOZ_CRASH/MOZ_ASSERT indicate logic violations — often exploitable
    if any(kw.lower() in output_lower for kw in MOZ_ASSERT_KEYWORDS):
        return max(base_severity, 4)
    # ASAN scariness score
    scariness = _parse_scariness(output)
    if scariness >= 60:
        return max(base_severity, 5)
    elif scariness >= 40:
        return max(base_severity, 4)
    return base_severity


def detect_issue(run_result: dict, config: dict) -> tuple:
    """Detect crashes with configurable keywords; returns (is_issue, reason, severity)."""
    if run_result["timed_out"]:
        # Check if there's ASAN output even on timeout (captured from buffered stderr)
        output_lower = run_result["output"].lower() if run_result["output"] else ""
        if output_lower:
            asan_keywords = config.get("asan_keywords", DEFAULT_ASAN_KEYWORDS)
            for keyword in asan_keywords:
                if keyword.lower() in output_lower:
                    return True, f"timeout+asan: {keyword}", 5
            for keyword in config["crash_keywords"]:
                if keyword.lower() in output_lower:
                    if keyword.lower() in ["segfault", "segmentation fault", "crash", "sigsegv"]:
                        return True, f"timeout+crash: {keyword}", 4
                    return True, f"timeout+crash: {keyword}", 3
        return True, "timeout", 1  # Timeouts are low-value DoS, not memory corruption

    if run_result["error"]:
        return True, f"error: {run_result['error']}", 2

    if run_result["exit_code"] != 0:
        output_lower = run_result["output"].lower()

        # Check for high-value sanitizer crashes FIRST
        severity = 1
        asan_keywords = config.get("asan_keywords", DEFAULT_ASAN_KEYWORDS)
        is_sanitizer = False
        for keyword in asan_keywords:
            if keyword.lower() in output_lower:
                severity = 5
                is_sanitizer = True

        # Only filter by ignore_keywords if NOT a sanitizer crash
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

        # Boost severity based on exploitability signals and ASAN scariness
        severity = _boost_severity_from_crash_type(run_result["output"], severity)

        return True, f"non-zero exit ({run_result['exit_code']})", severity

    output_lower = run_result["output"].lower()
    for keyword in config["crash_keywords"]:
        if keyword.lower() in output_lower:
            return True, f"crash keyword: {keyword}", 3

    return False, None, 0


class CrashDeduplicator:
    """Deduplicate crashes using stack signature hashing."""

    def __init__(self):
        """Initialize with empty signature set."""
        import threading
        self.seen = {}  # signature -> True
        self._lock = threading.Lock()

    def extract_signature(self, output: str, issue_reason: str) -> str:
        """Extract and normalize stack frames into an MD5 signature."""
        frames = []
        for line in output.splitlines():
            stripped = line.strip()
            if any(pat in stripped for pat in ["::", "->", ".cpp:", ".h:", "js::"]):
                normalized = re.sub(r'0x[0-9a-fA-F]+', 'N', stripped)
                normalized = re.sub(r'\b\d+\b', 'N', normalized)
                frames.append(normalized)
                if len(frames) >= 10:
                    break

        if frames:
            content = "\n".join(frames)
        elif output.strip():
            content = issue_reason + output[:1000]
        else:
            # Empty output (common for timeouts) — can't deduplicate reliably
            # Generate a unique signature so each gets saved
            import uuid
            content = issue_reason + uuid.uuid4().hex

        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def is_duplicate(self, output: str, issue_reason: str, crashes_dir: str) -> tuple:
        """Check signature against in-memory cache and saved crash files on disk."""
        sig = self.extract_signature(output, issue_reason)
        with self._lock:
            if sig in self.seen:
                return True, sig
            # Check filesystem
            for meta_path in glob.glob(os.path.join(crashes_dir, "*", "meta.json")):
                try:
                    with open(meta_path) as f:
                        meta = json.load(f)
                    if meta.get("signature") == sig:
                        self.seen[sig] = True
                        return True, sig
                except (json.JSONDecodeError, OSError):
                    continue
            # Claim this signature before releasing lock
            self.seen[sig] = True
            return False, sig

    def __repr__(self):
        """String representation."""
        return f"CrashDeduplicator(seen={len(self.seen)})"


def minimize_test_case(client, html_content, issue_reason, run_output):
    """Use LLM to minimize the crashing test case to a minimal reproducer."""
    prompt = f"""You are minimizing a browser fuzzing test case that triggered an issue in Firefox.

ISSUE TYPE: {issue_reason}
BROWSER OUTPUT (truncated):
{run_output[:3000]}

ORIGINAL HTML:
```html
{html_content}
```

Your task: Create the ABSOLUTE MINIMUM HTML that would still trigger this same issue.
- Remove ALL unnecessary elements, attributes, styles, and scripts
- Keep ONLY the essential code that causes the problem
- The result should be as small as possible while still reproducing the bug
- Add a comment at the top explaining what the minimal reproducer targets

Output ONLY the minimized HTML, nothing else."""

    response = client.messages.create(
        model=ANALYSIS_MODEL,
        max_tokens=4096,
        system="You are an expert at minimizing browser bug reproducers. Output raw HTML only, no markdown fences.",
        messages=[{"role": "user", "content": prompt}]
    )
    return extract_html(response.content[0].text)


def generate_report(client, html_content, minimized_html, issue_reason, run_output, severity):
    """Generate a professional Bugzilla-ready bug report."""
    severity_labels = {1: "Low", 2: "Medium-Low", 3: "Medium", 4: "High", 5: "Critical"}

    prompt = f"""You are a security researcher writing a bug report for Mozilla's Bugzilla.

ISSUE TYPE: {issue_reason}
SEVERITY ESTIMATE: {severity_labels.get(severity, "Unknown")}
BROWSER OUTPUT:
{run_output[:3000]}

ORIGINAL HTML ({len(html_content)} bytes):
```html
{html_content[:2000]}
```

MINIMIZED REPRODUCER ({len(minimized_html)} bytes):
```html
{minimized_html}
```

Write a professional, Bugzilla-ready bug report including:

1. **Summary**: One-line description of the bug
2. **Affected Component**: Best guess (Layout, DOM, JavaScript Engine, Graphics, etc.)
3. **Steps to Reproduce**: Numbered list
4. **Expected Result**: What should happen
5. **Actual Result**: What actually happened
6. **Technical Analysis**: Root cause hypothesis based on the output and code
7. **Security Impact**: If this could be exploitable, explain how
8. **Environment**: Note that Firefox version needs verification
9. **Attachments**: Reference the minimized HTML file

Be precise, technical, and professional. This may be submitted to a real bug bounty program."""

    response = client.messages.create(
        model=ANALYSIS_MODEL,
        max_tokens=2048,
        system="You are a professional security researcher who writes clear, actionable bug reports.",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text
