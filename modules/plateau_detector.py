from collections import deque


class PlateauDetector:
    """Detect when the fuzzer is stuck generating repetitive content."""

    def __init__(self, window=20, threshold=0.05):
        """Initialize with sliding window size and novelty rate threshold."""
        self.window = window
        self.threshold = threshold
        self._history = deque(maxlen=window)

    def update(self, was_novel: bool):
        """Record whether the latest test was novel."""
        self._history.append(was_novel)

    def is_plateau(self) -> bool:
        """True if novelty rate falls below threshold over a full window."""
        if len(self._history) < self.window:
            return False
        novelty_rate = sum(self._history) / len(self._history)
        return novelty_rate < self.threshold

    def get_plateau_prompt(self) -> str:
        """Return a strong diversity injection prompt to break out of plateau."""
        return (
            "CRITICAL DIVERSITY RESET: The fuzzer has detected a plateau — "
            "recent test cases are too similar to each other. You MUST completely "
            "change your approach. Pick a Firefox subsystem you have NOT targeted "
            "recently and use a fundamentally different technique. Consider: "
            "binary format parsing via Blob URLs, Service Worker interception, "
            "SharedArrayBuffer race conditions, CSS Houdini paint worklets, "
            "WASM memory boundary violations, cross-origin iframe edge cases, "
            "or Web Audio graph cycle creation. Be radically creative."
        )

    def get_stats(self) -> dict:
        """Return detector statistics."""
        fill = len(self._history)
        novelty_rate = sum(self._history) / fill if fill > 0 else 0.0
        return {
            "window_fill": fill,
            "novelty_rate": round(novelty_rate, 3),
            "is_plateau": self.is_plateau()
        }

    def __repr__(self):
        """String representation."""
        stats = self.get_stats()
        return f"PlateauDetector(fill={stats['window_fill']}/{self.window}, rate={stats['novelty_rate']}, plateau={stats['is_plateau']})"
