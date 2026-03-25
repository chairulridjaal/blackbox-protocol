import re
import threading
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ── Stop words: common HTML/JS boilerplate that every test shares ────────────
# These dominate the feature space and drown out the exploit-specific tokens.
_STOP_WORDS = frozenset([
    # HTML boilerplate
    "document", "window", "function", "return", "const", "let", "var",
    "true", "false", "null", "undefined", "new", "this", "for", "while",
    "if", "else", "try", "catch", "typeof", "instanceof", "class",
    "script", "html", "head", "body", "div", "span", "style",
    # Common DOM methods every test uses
    "createelement", "appendchild", "removechild", "queryselector",
    "getelementbyid", "getelementsbytagname", "addeventlistener",
    "removeeventlistener", "setattribute", "getattribute",
    "classname", "classlist", "innerhtml", "textcontent",
    "parentnode", "childnodes", "firstchild", "lastchild",
    "nextsibling", "previoussibling", "parentelement",
    "createtextnode", "clonenode", "contains", "insertbefore",
    "replacechild", "haschildnodes", "normalize",
    # Common patterns
    "console", "log", "error", "length", "push", "pop",
    "foreach", "map", "filter", "reduce", "from", "keys",
    "values", "entries", "math", "random", "floor", "ceil",
    "parseint", "parsefloat", "string", "number", "boolean",
    "object", "array", "date", "json", "stringify", "parse",
    "settimeout", "setinterval", "clearinterval", "cleartimeout",
    "requestanimationframe", "cancelanimationframe",
    "promise", "resolve", "reject", "then", "async", "await",
    "prototype", "constructor", "target", "property", "mechanism",
    "expected",
])


def _extract_script_body(html):
    """Extract only the JavaScript content from <script> tags and HTML comments.

    This strips the boilerplate HTML structure so we compare the actual
    exploit logic, not the shared wrapper that every test has.
    """
    parts = []

    # Extract HTML comment blocks (contain Target/Property/Mechanism metadata)
    for m in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
        parts.append(m.group(1))

    # Extract <script> bodies
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        parts.append(m.group(1))

    return "\n".join(parts) if parts else html


class NoveltyTracker:
    """TF-IDF novelty scoring for generated test cases.

    Key design decisions vs the previous version:
    1. Compares SCRIPT CONTENT ONLY — strips HTML boilerplate that all tests share
    2. Uses WORD n-grams (1,2) not char n-grams — captures API call patterns
    3. Uses JS/HTML STOP WORDS — removes tokens every test has (createElement, etc.)
    4. INCREMENTAL vectorizer — fits once on initial corpus, then only transforms
       new documents. Prevents IDF weight drift as the corpus grows.
    5. Corpus aging — drops oldest 25% when corpus is full, keeping the detector
       sensitive to recent patterns rather than ancient ones.
    """

    def __init__(self, threshold=0.65, max_corpus=500):
        """Initialize with similarity threshold and max corpus size.

        Args:
            threshold: Maximum cosine similarity allowed. Tests above this
                       are considered duplicates. Default 0.65 is looser than
                       the old 0.85 because we now compare script-only content
                       which has higher baseline similarity removed.
            max_corpus: Maximum number of tests to keep in the corpus.
        """
        self.threshold = threshold
        self.max_corpus = max_corpus
        self._corpus = []          # Raw script bodies
        self._vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),    # Unigrams + bigrams capture API call sequences
            max_features=8000,
            token_pattern=r"(?u)\b[a-zA-Z_]\w{2,}\b",  # 3+ char word tokens
            stop_words=list(_STOP_WORDS),
            sublinear_tf=True,     # log(1+tf) — dampens high-frequency terms
        )
        self._fitted = False       # Whether vectorizer has been fitted
        self._corpus_vecs = None   # Cached TF-IDF matrix for corpus
        self._lock = threading.Lock()
        self._total_checked = 0
        self._duplicates_skipped = 0
        self._refit_interval = 25  # Re-fit vectorizer every N additions
        self._since_last_refit = 0

    def _refit(self):
        """Re-fit the vectorizer on the current corpus and cache vectors."""
        if len(self._corpus) < 2:
            self._fitted = False
            self._corpus_vecs = None
            return
        self._corpus_vecs = self._vectorizer.fit_transform(self._corpus)
        self._fitted = True
        self._since_last_refit = 0

    def is_novel(self, html: str) -> tuple:
        """Check if HTML is novel against corpus; returns (is_novel, novelty_score).

        Extracts script content, compares against corpus using TF-IDF cosine
        similarity. Returns True if the test is sufficiently different from
        all existing corpus entries.
        """
        script = _extract_script_body(html)

        with self._lock:
            self._total_checked += 1

            # Bootstrap: accept the first few tests unconditionally
            if len(self._corpus) < 5:
                self._corpus.append(script)
                if len(self._corpus) == 5:
                    self._refit()
                return True, 1.0

            # If vectorizer isn't fitted yet, fit it now
            if not self._fitted:
                self._refit()

            # Transform the new document using the fitted vocabulary
            try:
                new_vec = self._vectorizer.transform([script])
            except Exception:
                # If transform fails (empty vocabulary etc), refit and retry
                self._refit()
                new_vec = self._vectorizer.transform([script])

            # Compare against all corpus vectors
            similarities = cosine_similarity(new_vec, self._corpus_vecs)[0]
            max_sim = float(similarities.max())
            novelty_score = 1.0 - max_sim

            if max_sim <= self.threshold:
                # Novel — add to corpus
                self._corpus.append(script)
                self._since_last_refit += 1

                # Corpus aging: drop oldest 25% when full
                if len(self._corpus) > self.max_corpus:
                    drop = len(self._corpus) // 4
                    self._corpus = self._corpus[drop:]
                    self._refit()  # Must refit after pruning
                elif self._since_last_refit >= self._refit_interval:
                    # Periodic refit to incorporate new documents into IDF
                    self._refit()
                else:
                    # Incrementally update corpus vectors (transform only)
                    self._corpus_vecs = self._vectorizer.transform(self._corpus)

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
                "duplicates_skipped": self._duplicates_skipped,
            }

    def __repr__(self):
        """String representation with stats."""
        stats = self.get_stats()
        return (
            f"NoveltyTracker(corpus={stats['corpus_size']}, "
            f"checked={stats['total_checked']}, "
            f"skipped={stats['duplicates_skipped']})"
        )
