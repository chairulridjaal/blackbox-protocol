import threading


SUBSYSTEMS = [
    "HTML5_parser", "CSS_layout", "JS_engine", "SVG_renderer",
    "Canvas_WebGL", "Web_Audio", "WebRTC", "DOM_events",
    "IndexedDB", "WebAssembly", "CSS_animations", "Shadow_DOM",
    "Intersection_Observer", "Service_Worker", "WebSockets",
    "Web_Animations", "XSLT_XPath", "WebTransport",
]


class SubsystemTracker:
    """Track which Firefox subsystems have been tested and crashed."""

    def __init__(self):
        """Initialize tracking counters for all subsystems."""
        self._lock = threading.RLock()
        self._test_counts = {s: 0 for s in SUBSYSTEMS}
        self._crash_counts = {s: 0 for s in SUBSYSTEMS}

    def record_test(self, subsystem: str):
        """Record that a test targeted this subsystem."""
        with self._lock:
            if subsystem in self._test_counts:
                self._test_counts[subsystem] += 1

    def record_crash(self, subsystem: str):
        """Record that a crash was found in this subsystem."""
        with self._lock:
            if subsystem in self._crash_counts:
                self._crash_counts[subsystem] += 1

    def get_underexplored(self, top_n=3) -> list:
        """Return the top_n least-explored subsystems by crash ratio, with test count as tiebreaker."""
        with self._lock:
            ratios = []
            for s in SUBSYSTEMS:
                test_count = self._test_counts[s]
                crash_hits = self._crash_counts[s]
                ratio = crash_hits / max(test_count, 1)
                # Use (ratio, test_count) tuple for sorting:
                # - Primary: lowest crash ratio (underexplored)
                # - Tiebreaker: fewest tests (least visited)
                ratios.append((s, ratio, test_count))
            ratios.sort(key=lambda x: (x[1], x[2]))
            return [s for s, _, _ in ratios[:top_n]]

    def build_context_prompt(self) -> str:
        """Build a context string with coverage table and targeting instruction."""
        with self._lock:
            lines = ["Current subsystem coverage:"]
            lines.append(f"{'Subsystem':<25} {'Tests':>6} {'Crashes':>8} {'Ratio':>7}")
            lines.append("-" * 50)
            for s in SUBSYSTEMS:
                t = self._test_counts[s]
                c = self._crash_counts[s]
                r = c / max(t, 1)
                lines.append(f"{s:<25} {t:>6} {c:>8} {r:>7.3f}")

            underexplored = self.get_underexplored(3)
            lines.append(f"\nTarget these underexplored subsystems: {', '.join(underexplored)}")
            return "\n".join(lines)

    def get_stats(self) -> dict:
        """Return summary statistics."""
        with self._lock:
            total_tests = sum(self._test_counts.values())
            total_crashes = sum(self._crash_counts.values())
            return {
                "total_tests": total_tests,
                "total_crashes": total_crashes,
                "test_counts": dict(self._test_counts),
                "crash_counts": dict(self._crash_counts)
            }

    def __repr__(self):
        """String representation."""
        stats = self.get_stats()
        return f"SubsystemTracker(tests={stats['total_tests']}, crashes={stats['total_crashes']})"
