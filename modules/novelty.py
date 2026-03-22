import threading
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class NoveltyTracker:
    """TF-IDF semantic novelty scoring for generated test cases."""

    def __init__(self, threshold=0.85, max_corpus=500):
        """Initialize with similarity threshold and max corpus size."""
        self.threshold = threshold
        self.max_corpus = max_corpus
        self._corpus = []
        self._vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 6),
            max_features=5000
        )
        self._lock = threading.Lock()
        self._total_checked = 0
        self._duplicates_skipped = 0

    def is_novel(self, html: str) -> tuple:
        """Check if HTML is novel against corpus; returns (is_novel, novelty_score)."""
        with self._lock:
            self._total_checked += 1

            if len(self._corpus) < 3:
                self._corpus.append(html)
                return True, 1.0

            corpus_with_new = self._corpus + [html]
            tfidf_matrix = self._vectorizer.fit_transform(corpus_with_new)

            new_vec = tfidf_matrix[-1]
            corpus_vecs = tfidf_matrix[:-1]
            similarities = cosine_similarity(new_vec, corpus_vecs)[0]
            max_sim = float(similarities.max())
            novelty_score = 1.0 - max_sim

            if novelty_score >= (1.0 - self.threshold):
                self._corpus.append(html)
                if len(self._corpus) > self.max_corpus:
                    self._corpus = self._corpus[-self.max_corpus:]
                return True, novelty_score
            else:
                self._duplicates_skipped += 1
                return False, novelty_score

    def get_stats(self) -> dict:
        """Return corpus statistics."""
        with self._lock:
            return {
                "corpus_size": len(self._corpus),
                "total_checked": self._total_checked,
                "duplicates_skipped": self._duplicates_skipped
            }

    def __repr__(self):
        """String representation with stats."""
        stats = self.get_stats()
        return f"NoveltyTracker(corpus={stats['corpus_size']}, checked={stats['total_checked']}, skipped={stats['duplicates_skipped']})"
