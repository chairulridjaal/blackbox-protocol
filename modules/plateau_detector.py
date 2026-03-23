import random
from collections import deque


class PlateauDetector:
    """Detect when the fuzzer is stuck generating repetitive content."""

    def __init__(self, window=8, threshold=0.1):
        """Initialize with sliding window size and novelty rate threshold.

        Args:
            window: Number of recent results to track (default 8, was 20).
            threshold: If the fraction of novel tests in the window drops
                       below this, we're in a plateau (default 0.1 = ≤1 novel
                       in last 8 tests).
        """
        self.window = window
        self.threshold = threshold
        self._history = deque(maxlen=window)
        self._plateau_count = 0  # Track how many times plateau triggered

    def update(self, was_novel: bool):
        """Record whether the latest test was novel."""
        self._history.append(was_novel)

    def is_plateau(self) -> bool:
        """True if novelty rate falls below threshold over a full window."""
        if len(self._history) < self.window:
            return False
        novelty_rate = sum(self._history) / len(self._history)
        return novelty_rate < self.threshold

    def mark_plateau_handled(self):
        """Record that a plateau was handled (for stats)."""
        self._plateau_count += 1

    def get_plateau_prompt(self) -> str:
        """Return a randomized diversity injection prompt to break out of plateau.

        Varies the prompt each time to avoid the LLM seeing identical
        instructions that it learns to pattern-match and ignore.
        """
        self.mark_plateau_handled()

        _techniques = [
            "Blob URL binary format parsing with DataView on crafted ArrayBuffers",
            "Service Worker interception with FetchEvent.respondWith() during navigation",
            "SharedArrayBuffer + Atomics race conditions across Worker boundaries",
            "CSS Houdini registerPaint() worklet with DOM mutations during paint",
            "WebTransport bidirectional streams with abrupt close during data transfer",
            "WebCodecs VideoDecoder with crafted H.264 NAL units and reset() during decode",
            "OffscreenCanvas.transferToImageBitmap() during WebGL context loss",
            "MediaSource + SourceBuffer.appendBuffer() with concurrent remove()",
            "ReadableStream BYOB reader with detached ArrayBuffer during pull",
            "EditContext API with simultaneous IME composition and DOM mutation",
            "Trusted Types createPolicy() with callback that modifies policy rules",
            "Navigation API navigate() with intercept() handler that triggers another navigation",
            "View Transitions API startViewTransition() callback that destroys captured elements",
            "Popover API togglePopover() during beforetoggle event with nested popovers",
        ]

        picked = random.sample(_techniques, 3)

        return (
            "CRITICAL DIVERSITY RESET: The last several test cases were all too similar. "
            "You MUST completely change your approach — different subsystem, different "
            "vulnerability class, different C++ code path. Avoid ANY pattern you've "
            "used before. Try one of these unexplored techniques:\n"
            f"  1. {picked[0]}\n"
            f"  2. {picked[1]}\n"
            f"  3. {picked[2]}\n"
            "Think about what Firefox C++ code path each of these exercises and "
            "what invariant could be violated."
        )

    def get_stats(self) -> dict:
        """Return detector statistics."""
        fill = len(self._history)
        novelty_rate = sum(self._history) / fill if fill > 0 else 0.0
        return {
            "window_fill": fill,
            "novelty_rate": round(novelty_rate, 3),
            "is_plateau": self.is_plateau(),
            "plateau_triggers": self._plateau_count,
        }

    def __repr__(self):
        """String representation."""
        stats = self.get_stats()
        return (
            f"PlateauDetector(fill={stats['window_fill']}/{self.window}, "
            f"rate={stats['novelty_rate']}, plateau={stats['is_plateau']}, "
            f"triggers={stats['plateau_triggers']})"
        )
