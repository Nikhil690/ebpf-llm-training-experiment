# Fine-tuning an eBPF Specialist Model from Scratch

> **This is a personal research experiment.** The goal is to learn the fine-tuning pipeline end-to-end — dataset construction, evaluation design, and training. The results are from a narrow benchmark on a single small model. This is not production tooling and the model is not intended for general use.

eBPF has become the backbone of modern Linux observability, networking, and security. Tools like Cilium, Tetragon, Tracee, and Falco all run eBPF programs under the hood. But ask any general-purpose LLM to write eBPF code and you get hallucinated API names, wrong macro signatures, and code that won't compile.

This post documents building a domain-specialist eBPF coding model from scratch — dataset, evaluation benchmark, training, and results.

---

## The Problem

eBPF is niche enough that general LLMs fail on the specifics:

- **aya (Rust)**: uses `#[map]`, `#[xdp]`, `#[kprobe]` proc-macro attributes — models invent `BPF_MAP_DEF` from C
- **cilium/ebpf (Go)**: `ebpf.LoadCollectionSpec`, `link.AttachXDP` — models hallucinate `ebpf.OpenMap`, `prog.AttachXDP`
- **libbpf (C)**: CO-RE requires `bpf_core_read`, vmlinux.h BTF types — models use old non-portable kernel headers
- API versions change fast; training data is stale

A model that knows eBPF theory but generates non-compiling code is not useful.

---

## Step 1: Building the Dataset

### Source Repos (19 total)

```
aya, cilium/ebpf, libbpf, libbpf-bootstrap, libbpf-rs,
aquasecurity/tracee, cilium/tetragon, iovisor/bcc,
grafana/beyla, deepflowio/deepflow, redbpf, bpfman, retis,
bpf-developer-tutorial, learning-ebpf, eunomia-bpf,
bpf-perf-tools-book, aya-rs/book, libbpf-rs
```

### Extraction

Each repo was scraped for `.rs`, `.c`, `.h`, `.go`, `.py`, `.md`, `.rst` files. Files were chunked by logical boundaries (function-level for code, section-level for docs).

**Key insight from v1:** The first dataset had noise — non-eBPF source files labeled as eBPF code (test harnesses, build scripts, generic utilities). This hurt model quality. For v2 we added per-language eBPF signal filters:

- **C/H files:** must contain `SEC(`, `BPF_MAP_TYPE_`, `bpf_helpers.h`, `vmlinux.h`, or similar
- **Rust files:** must contain `#[xdp]`, `#[kprobe]`, `use aya::`, `EbpfLoader`, or similar
- **Go files:** must contain `cilium/ebpf`, `ebpf.LoadCollection`, `link.AttachXDP`, or similar

Noise filters also removed:
- Non-eBPF markdown (CODE_OF_CONDUCT, CHANGELOG, LICENSE)
- Chunks under 50 characters

Result: **12,262 clean chunks** (vs 17,887 noisy chunks in v1)

### Synthetic Q&A Generation

A local **Qwen3.5:27B** running via llama-server generated instruction pairs from each chunk. Per-chunk prompts were varied by chunk type:

- `tutorial_section` → concept explanation + code walkthrough
- `doc_code` → API explanation + usage example
- `raw_code` → code analysis

12 concurrent worker threads, temperature varied by style (0.3 for code, 0.6 for explanations), max 768 tokens per answer.

Result: **~17,000 synthetic samples**

### Deduplication

Quality filter:
- Min 150 chars answer, min 30 words
- Must contain eBPF signal word in question+answer

Exact dedup by MD5(question + answer) and MD5(question).

Near-dedup with MinHash LSH (128 hash functions, Jaccard threshold 0.85).

Result: **6,412 clean samples** in ShareGPT format → uploaded to [Nikhil69/ebpf-instruct-v2](https://huggingface.co/datasets/Nikhil69/ebpf-instruct-v2)

---

## Step 2: eBPF-HumanEval Benchmark

Before training, we needed a fair way to measure improvement. The key insight: **keyword matching is not enough**. A model that mentions "XDP" and "map" might still produce code that doesn't compile.

### 40 Problems Across 5 Categories

| Category | Count | Check Method |
|---|---|---|
| aya_kernel | 10 | `cargo +nightly check --target bpfel-unknown-none` |
| aya_user | 4 | `cargo check` |
| cilium_go | 10 | `go build ./...` |
| libbpf_c | 10 | `clang -target bpf` with vmlinux.h |
| conceptual | 6 | keyword coverage (≥50% required) |

Compilation-based pass@1: the model's output must actually compile.

### Infrastructure Challenges

**Problem 1: Cargo compiles from scratch each time (90s per check)**
Solution: pre-build template Cargo projects once, pass `--target-dir` pointing to the shared compiled cache. Subsequent checks reuse proc-macros → 5-10s.

**Problem 2: bpfel-unknown-none not available in stable Rust**
Solution: `cargo +nightly check -Z build-std=core --target bpfel-unknown-none`

**Problem 3: C programs need kernel BTF types**
Solution: generate `vmlinux.h` from the running kernel via `bpftool btf dump file /sys/kernel/btf/vmlinux format c`. 200k+ lines covering all kernel structs. All C prompts specify CO-RE style.

**Problem 4: Go missing go.sum on first run**
Solution: pre-warm template with `go mod tidy`, commit go.sum, copy to temp dir per eval.

---

## Step 3: Baseline Evaluation

Before any training, evaluate the raw model.

**Qwen3.5-4B baseline:**
```
Overall pass@1 : 5/40 (12.5%)

  aya_kernel    0/10  (0%)
  aya_user      0/4   (0%)
  cilium_go     0/10  (0%)
  conceptual    5/6   (83%)
  libbpf_c      0/10  (0%)
```

The model knows eBPF theory but invents APIs for every framework. Classic hallucination on niche libraries.

Notable failures:
- All `aya_kernel` problems failed on `expected 'static'` — model outputs Markdown-fenced code or wrong struct syntax
- All `cilium_go` problems failed importing `github.com/cilium/ebpf/bpf` which doesn't exist
- All `libbpf_c` problems failed on basic syntax — model uses `__max_entries(1)` instead of `__uint(max_entries, 1)`

---

## Step 4: Fine-tuning with Unsloth

### Setup

Fine-tuning was done via [Unsloth Studio](https://github.com/unslothai/unsloth) on an NVIDIA GH200 (97GB HBM).

Dataset: `Nikhil69/ebpf-instruct-v2`, ShareGPT format, 6,412 samples.

### Qwen3.5-4B LoRA Config (v2)

| Parameter | Value |
|---|---|
| Epochs | 3 |
| Context length | 2048 |
| Batch size | 4 |
| Gradient accumulation | 4 (effective batch 16) |
| Learning rate | 2e-4 |
| LR scheduler | cosine |
| Optimizer | AdamW 8-bit |
| Warmup steps | 100 |
| LoRA rank | 32 |
| LoRA alpha | 32 |
| LoRA dropout | 0 |
| Target modules | q/k/v/o/gate/up/down_proj |

Training loss: 0.98 → 0.77 at step 307 → converged to ~0.5–0.6 by end of run.

---

## Step 5: Post-training Results

```
Overall pass@1 : 9/40 (22.5%)   [+80% relative over baseline]

  aya_kernel    0/10  (0%)
  aya_user      0/4   (0%)
  cilium_go     0/10  (0%)
  conceptual    6/6   (100%)
  libbpf_c      3/10  (30%)
```

**+4 total passes vs baseline (+80% relative improvement).**

- `libbpf_c`: 0 → 3 — the model now writes correct CO-RE style programs with proper `SEC()` macros and map definitions
- `conceptual`: 5 → 6 — all 6 conceptual questions answered correctly
- `aya_kernel` / `aya_user` / `cilium_go` still 0 — these need more targeted training data

---

## Key Findings

### 1. Dataset quality > dataset size

v1 had 10k+ samples but with non-eBPF code mislabeled as eBPF. v2 had 6,412 samples with clean signal. The smaller cleaner dataset produced better results.

### 2. aya (Rust eBPF) is the hardest category — 0% across all tests

Rust eBPF is underrepresented in pretraining data and in our scraped dataset. The `aya` crate's proc-macro system (`#[map]`, `#[xdp]`) is unfamiliar to every model. This is the next gap to close — need more compilable aya examples.

### 3. Compilation-based eval catches what keyword matching misses

Many responses mentioned correct terms but used wrong API signatures, wrong argument counts, or fabricated functions. Pass@1 on actual compilation is the only reliable signal.

### 4. Pre-building template deps is critical

Without shared target directories, each cargo check: 90s × 40 problems = 60 minutes per eval. With pre-built caches: 5-10s per problem → ~8 minutes total.

### 5. Thinking mode in reasoning models needs explicit handling

Models with chain-of-thought (`<think>...</think>`) need the thinking stripped from output before compilation. Sending `enable_thinking: false` via API can silently return empty responses — safer to strip tags in post-processing.

---

## What's Next

- **aya-focused dataset v3**: more compilable aya kernel/user examples, correct `#[map]` / `#[xdp]` patterns
- **cilium/ebpf Go**: more examples using `rlimit.RemoveMemlock()`, correct `link.AttachXDP` signatures
- **Larger base model**: same pipeline on a 7B or 14B model
- **More eval problems**: 40 is a thin benchmark — expand to 200+ with multi-file programs
- **Pass@k**: run each problem k times for a more robust signal
