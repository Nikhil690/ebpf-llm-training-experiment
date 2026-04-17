"""
Phase 2: Synthetic Q&A generation using local Qwen3-Coder (llama-server).

Reads:  dataset_raw/chunks.jsonl
Writes: dataset_raw/synthetic.jsonl

Each output line is a ShareGPT-format training sample:
{
  "conversations": [
    {"from": "system", "value": "<system prompt>"},
    {"from": "human",  "value": "<question>"},
    {"from": "gpt",    "value": "<answer>"}
  ],
  "source_chunk_id": "<chunk id>"
}

Generation strategy per chunk kind:
  tutorial_section → 2 samples: concept explanation + "how to" question
  doc_code         → 2 samples: explain the code + use-case question
  raw_code         → 1 sample:  explain what this code does
"""

import json
import re
import sys
import time
import random
import threading
import multiprocessing
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from openai import OpenAI

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

BASE       = Path("/data/First_Dataset")
CHUNKS_IN  = BASE / "dataset_raw" / "chunks.jsonl"
OUT        = BASE / "dataset_raw" / "synthetic_v2.jsonl"
FAILED_OUT = BASE / "dataset_raw" / "failed_chunks_v2.jsonl"

LLAMA_URL  = "http://localhost:8080/v1"
MODEL      = "qwen3.5:27b"

# Concurrency — Qwen3-Coder is 79B; GH200 can handle ~8-12 concurrent requests
# before latency degrades. Start conservative, raise if GPU util stays low.
MAX_WORKERS = 12  # slightly above --parallel 8 to keep all slots fed

# Skip chunks shorter than this — not enough context for good Q&A
MIN_CONTENT_CHARS = 150

# Retry settings
MAX_RETRIES = 3
RETRY_DELAY = 2.0

SYSTEM_PROMPT = """\
You are an expert eBPF developer and educator with deep knowledge of:
- eBPF kernel programs (XDP, TC, kprobes, tracepoints, LSM, cgroup hooks)
- Rust eBPF: aya framework, aya-ebpf, libbpf-rs, redbpf
- Go eBPF: cilium/ebpf library, bpf2go, Tetragon, Beyla
- C eBPF: libbpf, BCC, libbpf-bootstrap
- eBPF maps, BTF, CO-RE, ring buffers, perf events
- Kernel verifier, program types, helper functions
- Real-world eBPF use cases: observability, security, networking

You write precise, idiomatic code and clear technical explanations.\
"""

# ──────────────────────────────────────────────
# Prompt templates per chunk kind
# ──────────────────────────────────────────────

def prompts_for_chunk(chunk: dict) -> list[dict]:
    """Return list of {"instruction": str, "style": str} for this chunk."""
    kind  = chunk["kind"]
    title = chunk["title"]
    body  = chunk["body"].strip()
    codes = chunk.get("code", [])
    lang  = chunk["lang"]
    repo  = chunk["repo"]
    code  = codes[0] if codes else ""

    framework = _detect_framework(repo, lang)
    prompts = []

    if kind == "tutorial_section":
        if body:
            prompts.append({
                "instruction": f"Explain the concept of '{title}' in the context of eBPF development{' using ' + framework if framework else ''}.",
                "style": "concept",
                "context": body[:1500],
            })
        if code:
            prompts.append({
                "instruction": f"Walk me through this eBPF code step by step and explain what it does:\n\n```{lang}\n{code[:1200]}\n```",
                "style": "code_walkthrough",
                "context": body[:800],
            })

    elif kind == "doc_code":
        if code:
            prompts.append({
                "instruction": f"Explain what `{title}` does in {framework or 'eBPF'} and show how to use it.",
                "style": "api_explain",
                "context": f"Documentation:\n{body[:600]}\n\nSource:\n```{lang}\n{code[:1200]}\n```",
            })
            prompts.append({
                "instruction": f"Write a practical example showing how to use `{title}` from the {framework or 'eBPF'} API. Include the key steps and any important caveats.",
                "style": "usage_example",
                "context": f"```{lang}\n{code[:1200]}\n```",
            })

    elif kind == "raw_code":
        if code:
            prompts.append({
                "instruction": f"Analyze this {lang} eBPF code and explain what it does, how it works, and what eBPF concepts it demonstrates:\n\n```{lang}\n{code[:1500]}\n```",
                "style": "code_analysis",
                "context": "",
            })

    return prompts


def _detect_framework(repo: str, lang: str) -> str:
    mapping = {
        "aya":                  "the aya Rust eBPF framework",
        "book":                 "the aya Rust eBPF framework",
        "libbpf-rs":            "libbpf-rs (Rust bindings for libbpf)",
        "redbpf":               "the redbpf Rust eBPF framework",
        "bpfman":               "bpfman (eBPF program lifecycle manager)",
        "retis":                "retis (eBPF network tracing)",
        "ebpf":                 "the cilium/ebpf Go library",
        "tetragon":             "Cilium Tetragon",
        "beyla":                "Grafana Beyla",
        "tracee":               "Aqua Security Tracee",
        "deepflow":             "DeepFlow",
        "libbpf-bootstrap":     "libbpf (C)",
        "bcc":                  "BCC (BPF Compiler Collection)",
        "bpf-developer-tutorial": "libbpf (C)",
        "eunomia-bpf":          "eunomia-bpf",
        "learning-ebpf":        "libbpf (C)",
        "bpf-perf-tools-book":  "BPF performance tools",
    }
    return mapping.get(repo, "")


# ──────────────────────────────────────────────
# LLM call
# ──────────────────────────────────────────────

_client_local = threading.local()

def get_client() -> OpenAI:
    if not hasattr(_client_local, "client"):
        _client_local.client = OpenAI(base_url=LLAMA_URL, api_key="not-needed")
    return _client_local.client


def call_llm(instruction: str, context: str, style: str) -> str:
    user_msg = instruction
    if context:
        user_msg = f"{context}\n\n---\n\n{instruction}"

    # Adjust temperature by style
    temp = {
        "concept":          0.6,
        "code_walkthrough": 0.3,
        "api_explain":      0.4,
        "usage_example":    0.4,
        "code_analysis":    0.3,
    }.get(style, 0.5)

    for attempt in range(MAX_RETRIES):
        try:
            resp = get_client().chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system",    "content": SYSTEM_PROMPT},
                    {"role": "user",      "content": user_msg},
                ],
                temperature=temp,
                max_tokens=768,
                timeout=120,
            )
            answer = resp.choices[0].message.content.strip()
            # Strip <think>...</think> blocks if model outputs chain-of-thought
            answer = re.sub(r"<think>.*?</think>", "", answer, flags=re.DOTALL).strip()
            if len(answer) < 40:
                raise ValueError(f"Answer too short: {answer!r}")
            return answer
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
            else:
                raise


# ──────────────────────────────────────────────
# Per-chunk worker
# ──────────────────────────────────────────────

def process_chunk(chunk: dict) -> tuple[list[dict], dict | None]:
    """Returns (samples, failed_chunk_or_None)."""
    content = (chunk.get("body", "") + " ".join(chunk.get("code", [])))
    if len(content) < MIN_CONTENT_CHARS:
        return [], None

    prompts = prompts_for_chunk(chunk)
    if not prompts:
        return [], None

    samples = []
    for p in prompts:
        try:
            answer = call_llm(p["instruction"], p["context"], p["style"])
            samples.append({
                "conversations": [
                    {"from": "system", "value": SYSTEM_PROMPT},
                    {"from": "human",  "value": p["instruction"]},
                    {"from": "gpt",    "value": answer},
                ],
                "source_chunk_id": chunk["id"],
                "repo":  chunk["repo"],
                "style": p["style"],
            })
        except Exception as e:
            return samples, {"chunk_id": chunk["id"], "error": str(e), "repo": chunk["repo"]}

    return samples, None


# ──────────────────────────────────────────────
# Resume support
# ──────────────────────────────────────────────

def load_done_ids() -> set:
    done = set()
    if OUT.exists():
        with open(OUT) as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    done.add(obj["source_chunk_id"])
                except Exception:
                    pass
    return done


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    if not CHUNKS_IN.exists():
        print(f"ERROR: {CHUNKS_IN} not found. Run extract.py first.")
        sys.exit(1)

    chunks = []
    with open(CHUNKS_IN) as f:
        for line in f:
            try:
                chunks.append(json.loads(line))
            except Exception:
                pass

    print(f"Loaded {len(chunks):,} chunks")

    done_ids = load_done_ids()
    if done_ids:
        print(f"Resuming — {len(done_ids):,} chunks already done")

    pending = [c for c in chunks if c["id"] not in done_ids]
    print(f"Pending: {len(pending):,} chunks  |  Workers: {MAX_WORKERS}")
    print(f"Model: {MODEL}  @  {LLAMA_URL}\n")

    total_samples = 0
    total_failed  = 0

    out_lock = threading.Lock()

    with open(OUT, "a") as out_f, \
         open(FAILED_OUT, "a") as fail_f, \
         ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool, \
         tqdm(total=len(pending), desc="Generating", unit="chunk") as pbar:

        futures = {pool.submit(process_chunk, c): c for c in pending}

        for future in as_completed(futures):
            samples, failed = future.result()
            with out_lock:
                for s in samples:
                    out_f.write(json.dumps(s) + "\n")
                    total_samples += 1
                if failed:
                    fail_f.write(json.dumps(failed) + "\n")
                    total_failed += 1
            pbar.update(1)
            pbar.set_postfix(samples=total_samples, failed=total_failed)

    print(f"\nDone.")
    print(f"  Samples generated : {total_samples:,}")
    print(f"  Failed chunks     : {total_failed:,}")
    print(f"  Output            : {OUT}")


if __name__ == "__main__":
    main()
