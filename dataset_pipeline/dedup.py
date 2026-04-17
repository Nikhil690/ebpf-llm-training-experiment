"""
Phase 3: Deduplication + Quality Filtering

Reads:  dataset_raw/synthetic.jsonl
Writes: dataset_raw/clean.jsonl

Steps:
  1. Exact dedup       — remove identical (instruction, response) pairs
  2. Quality filter    — drop samples with short/broken answers
  3. Near-dedup        — MinHash LSH to remove near-duplicate questions
  4. Stats report      — show what was kept/dropped and why
"""

import json
import re
import hashlib
import multiprocessing as mp
from pathlib import Path
from collections import Counter
from tqdm import tqdm

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

BASE     = Path("/data/First_Dataset")
IN_FILE  = BASE / "dataset_raw" / "synthetic_v2.jsonl"
OUT_FILE = BASE / "dataset_raw" / "clean_v2.jsonl"

# Quality thresholds
MIN_ANSWER_CHARS   = 150    # drop very short answers
MIN_ANSWER_WORDS   = 30     # drop answers with too few words
MIN_QUESTION_CHARS = 20     # drop trivial questions
MAX_ANSWER_CHARS   = 8000   # drop runaway responses

# Near-dedup: Jaccard similarity threshold (0.0–1.0)
# 0.85 = two questions sharing 85% of their shingles are considered duplicates
SIMILARITY_THRESHOLD = 0.85
SHINGLE_SIZE         = 5    # character n-gram size
NUM_HASH_FUNCS       = 128  # MinHash signature size

WORKERS = min(64, mp.cpu_count())

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def load_samples(path: Path) -> list[dict]:
    samples = []
    with open(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  Skipping malformed line {i}: {e}")
    return samples


def get_turns(sample: dict) -> tuple[str, str]:
    convs = sample.get("conversations", [])
    question = next((c["value"] for c in convs if c["from"] == "human"), "")
    answer   = next((c["value"] for c in convs if c["from"] == "gpt"), "")
    return question, answer


def exact_hash(question: str, answer: str) -> str:
    return hashlib.md5(f"{question}|||{answer}".encode()).hexdigest()


def question_hash(question: str) -> str:
    # Normalize whitespace and case for question dedup
    q = re.sub(r"\s+", " ", question.strip().lower())
    return hashlib.md5(q.encode()).hexdigest()


# ──────────────────────────────────────────────
# Quality filter
# ──────────────────────────────────────────────

# Signals of a bad/incomplete answer
BAD_ANSWER_PATTERNS = re.compile(
    r"^(I (don't|cannot|can't)|Sorry|I'm not sure|As an AI|I apologize)",
    re.IGNORECASE,
)

INCOMPLETE_PATTERNS = re.compile(
    r"\.\.\.$|to be continued|continued in part|end of response",
    re.IGNORECASE,
)


def quality_check(sample: dict) -> tuple[bool, str]:
    """Returns (is_good, reason_if_bad)."""
    question, answer = get_turns(sample)

    if len(question) < MIN_QUESTION_CHARS:
        return False, "question_too_short"

    if len(answer) < MIN_ANSWER_CHARS:
        return False, "answer_too_short"

    if len(answer.split()) < MIN_ANSWER_WORDS:
        return False, "answer_too_few_words"

    if len(answer) > MAX_ANSWER_CHARS:
        return False, "answer_too_long"

    if BAD_ANSWER_PATTERNS.search(answer[:100]):
        return False, "bad_answer_pattern"

    if INCOMPLETE_PATTERNS.search(answer[-100:]):
        return False, "incomplete_answer"

    # Must have some eBPF signal in question or answer
    ebpf_signal = re.compile(
        r"\bebpf\b|\bbpf\b|\bxdp\b|\bkprobe\b|\btracepoint\b|\baya\b|"
        r"\blibbpf\b|\bcilium\b|\bmap\b|\bprobe\b|\bsyscall\b|\bverifier\b|"
        r"\bbtf\b|\bco-re\b|\bring.buf|\bperf.event\b|\bsockmap\b|\bcgroup\b",
        re.IGNORECASE,
    )
    combined = question + " " + answer[:500]
    if not ebpf_signal.search(combined):
        return False, "no_ebpf_signal"

    return True, ""


# ──────────────────────────────────────────────
# MinHash near-dedup
# ──────────────────────────────────────────────

import random
import struct

# Pre-generate hash parameters once
_rng = random.Random(42)
_HASH_PARAMS = [
    (_rng.randint(1, (1 << 31) - 1), _rng.randint(0, (1 << 31) - 1))
    for _ in range(NUM_HASH_FUNCS)
]
_LARGE_PRIME = (1 << 31) - 1


def shingles(text: str, k: int = SHINGLE_SIZE) -> set:
    text = re.sub(r"\s+", " ", text.lower().strip())
    return {text[i:i+k] for i in range(len(text) - k + 1)}


def minhash(text: str) -> list[int]:
    sh = shingles(text)
    if not sh:
        return [0] * NUM_HASH_FUNCS
    hashed = [hash(s) & 0x7FFFFFFF for s in sh]
    sig = []
    for a, b in _HASH_PARAMS:
        sig.append(min((a * h + b) % _LARGE_PRIME for h in hashed))
    return sig


def jaccard_estimate(sig1: list[int], sig2: list[int]) -> float:
    return sum(a == b for a, b in zip(sig1, sig2)) / NUM_HASH_FUNCS


class LSHIndex:
    """Locality-Sensitive Hashing for fast near-duplicate detection."""

    def __init__(self, num_bands: int = 32):
        self.num_bands = num_bands
        self.rows_per_band = NUM_HASH_FUNCS // num_bands
        self.buckets: dict[tuple, list[int]] = {}

    def add(self, idx: int, sig: list[int]) -> list[int]:
        """Add signature, return list of candidate near-duplicate indices."""
        candidates = set()
        for band in range(self.num_bands):
            start = band * self.rows_per_band
            end   = start + self.rows_per_band
            key   = (band,) + tuple(sig[start:end])
            if key in self.buckets:
                candidates.update(self.buckets[key])
            else:
                self.buckets[key] = []
            self.buckets[key].append(idx)
        return list(candidates)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print(f"Loading {IN_FILE}...")
    samples = load_samples(IN_FILE)
    print(f"Loaded {len(samples):,} samples\n")

    dropped = Counter()
    kept = []

    # ── Step 1: Quality filter ──────────────────
    print("Step 1: Quality filtering...")
    quality_passed = []
    for s in tqdm(samples, desc="Quality"):
        ok, reason = quality_check(s)
        if ok:
            quality_passed.append(s)
        else:
            dropped[f"quality:{reason}"] += 1

    print(f"  Passed : {len(quality_passed):,}")
    print(f"  Dropped: {len(samples) - len(quality_passed):,}\n")

    # ── Step 2: Exact dedup ─────────────────────
    print("Step 2: Exact deduplication...")
    exact_seen = set()
    q_seen = set()
    exact_passed = []
    for s in tqdm(quality_passed, desc="Exact dedup"):
        q, a = get_turns(s)
        eh = exact_hash(q, a)
        qh = question_hash(q)
        if eh in exact_seen:
            dropped["exact:duplicate_qa"] += 1
        elif qh in q_seen:
            dropped["exact:duplicate_question"] += 1
        else:
            exact_seen.add(eh)
            q_seen.add(qh)
            exact_passed.append(s)

    print(f"  Passed : {len(exact_passed):,}")
    print(f"  Dropped: {len(quality_passed) - len(exact_passed):,}\n")

    # ── Step 3: Near-dedup via MinHash LSH ──────
    print("Step 3: Near-dedup (MinHash LSH)...")
    print(f"  Computing {NUM_HASH_FUNCS}-dim MinHash signatures with {WORKERS} workers...")

    questions = [get_turns(s)[0] for s in exact_passed]

    with mp.Pool(WORKERS) as pool:
        signatures = list(tqdm(
            pool.imap(minhash, questions, chunksize=64),
            total=len(questions),
            desc="MinHash",
        ))

    print("  Running LSH near-duplicate detection...")
    lsh = LSHIndex(num_bands=32)
    near_dup_ids = set()

    for i, sig in enumerate(tqdm(signatures, desc="LSH")):
        if i in near_dup_ids:
            continue
        candidates = lsh.add(i, sig)
        for j in candidates:
            if j != i and j not in near_dup_ids:
                sim = jaccard_estimate(signatures[i], signatures[j])
                if sim >= SIMILARITY_THRESHOLD:
                    near_dup_ids.add(j)  # keep i, drop j
                    dropped["neardup:similar_question"] += 1

    near_passed = [s for i, s in enumerate(exact_passed) if i not in near_dup_ids]
    print(f"  Passed : {len(near_passed):,}")
    print(f"  Dropped: {len(near_dup_ids):,}\n")

    # ── Step 4: Write output ────────────────────
    print(f"Writing {OUT_FILE}...")
    with open(OUT_FILE, "w") as f:
        for s in near_passed:
            f.write(json.dumps(s) + "\n")

    # ── Report ──────────────────────────────────
    print(f"\n{'='*50}")
    print(f"FINAL DATASET: {len(near_passed):,} samples")
    print(f"Removed      : {len(samples) - len(near_passed):,} ({(len(samples)-len(near_passed))/len(samples)*100:.1f}%)")
    print(f"Output size  : {OUT_FILE.stat().st_size / 1e6:.1f} MB")
    print(f"\nDrop reasons:")
    for reason, count in sorted(dropped.items(), key=lambda x: -x[1]):
        print(f"  {reason:<35} {count:>6}")

    # Per-repo breakdown of final dataset
    repo_counts: Counter = Counter()
    style_counts: Counter = Counter()
    for s in near_passed:
        repo_counts[s.get("repo", "unknown")] += 1
        style_counts[s.get("style", "unknown")] += 1

    print(f"\nFinal samples by repo:")
    for repo, n in repo_counts.most_common():
        pct = n / len(near_passed) * 100
        print(f"  {repo:<30} {n:>6}  ({pct:.1f}%)")

    print(f"\nFinal samples by style:")
    for style, n in style_counts.most_common():
        print(f"  {style:<25} {n:>6}")


if __name__ == "__main__":
    main()
