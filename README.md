# eBPF Specialist LLM

> **⚠️ Experimental Research Project**
> This is a personal research experiment to explore domain-specific fine-tuning — not a production-ready tool. The fine-tuned model is not published for general use. Results are from a narrow 40-problem benchmark on a single 4B model. Do not use this as a basis for production tooling decisions.

Fine-tuning a domain-specialist coding model for eBPF development from scratch — dataset, evaluation benchmark, and training results.

## What This Is

Most LLMs hallucinate eBPF APIs. This project builds a model that can actually write compilable eBPF code across four frameworks: **aya (Rust)**, **cilium/ebpf (Go)**, **libbpf (C)**, and conceptual explanations.

**Pipeline:**
1. Scrape 19 eBPF open-source repos → extract code/doc chunks
2. Generate synthetic Q&A using a local LLM (Qwen3.5:27B via llama-server)
3. Deduplicate and quality-filter → 6,412 clean samples
4. Fine-tune Qwen3.5-4B with Unsloth LoRA (3 epochs)
5. Evaluate with compilation-based pass@1 benchmark

## Results

| Model | Params | pass@1 | aya_kernel | aya_user | cilium_go | libbpf_c | conceptual |
|---|---|---|---|---|---|---|---|
| Qwen3.5-4B baseline | 4B | 12.5% (5/40) | 0% | 0% | 0% | 0% | 83% |
| Qwen3.5-4B fine-tuned | 4B | 22.5% (9/40) | 0% | 0% | 0% | 30% | 100% |
| **Qwen3.5-4B fine-tuned + post-processing** | **4B** | **32.5% (13/40)** | **0%** | **0%** | **0%** | **70%** | **100%** |
| Gemma-4-31B baseline | 31B | 35.0% (14/40) | 0% | 0% | 20% | 60% | 100% |
| Gemma-4-31B fine-tuned | 31B | 35.0% (14/40) | 0% | 0% | 30% | 50% | 100% |

Fine-tuning alone improved pass@1 by **+10pp** (+80% relative).  
With IDE-style post-processing (auto-inject missing C includes, fix unused Go imports): **+20pp** over baseline.

Gemma-4-31B (31B params) scored 35% at baseline — but fine-tuning on the same v2 dataset gave **0pp improvement**. The synthetic data is optimized for a 4B model's failure modes and doesn't meaningfully shift a larger model's weights.

> Post-processing applies the same fixes an IDE linter would — adding missing `#include <bpf/bpf_endian.h>` when `bpf_htons` is used, injecting missing Go sub-package imports. The model demonstrates correct API knowledge; the fixer handles last-mile syntactic omissions.

See [docs/results.md](docs/results.md) for full per-problem breakdown.

## Repository Structure

```
ebpf-specialist-llm/
├── dataset_pipeline/       # Data extraction, synthesis, deduplication
│   ├── extract.py          # Scrape repos → chunks.jsonl
│   ├── synthesize.py       # Generate Q&A pairs via local LLM
│   ├── dedup.py            # Quality filter + deduplication
│   └── requirements.txt
├── eval/                   # eBPF-HumanEval benchmark
│   ├── eval.py             # Main evaluation script
│   ├── problems.jsonl      # 40 eBPF coding problems
│   ├── templates/          # Cargo/Go project templates for compilation
│   ├── results/            # Benchmark results
│   └── requirements.txt
└── docs/
    ├── blog_post.md        # Full write-up
    ├── dataset.md          # Dataset construction details
    ├── eval_design.md      # Evaluation methodology
    └── results.md          # All model results
```

## Dataset

Available on HuggingFace: [Nikhil69/ebpf-instruct-v2](https://huggingface.co/datasets/Nikhil69/ebpf-instruct)

- **6,412** ShareGPT-format instruction pairs
- Covers: aya kernel/user, cilium/ebpf Go, libbpf C, BCC Python, conceptual eBPF
- Generated from **19 repos**: aya, libbpf, tetragon, cilium, tracee, bcc, redbpf, beyla, deepflow, bpfman, retis, libbpf-rs, libbpf-bootstrap, bpf-developer-tutorial, learning-ebpf, eunomia-bpf, bpf-perf-tools-book
- Cleaned with eBPF signal filters (no non-eBPF code mislabeled as eBPF)

## Quick Start

### Dataset Pipeline

```bash
cd dataset_pipeline
pip install -r requirements.txt

# 1. Extract chunks from cloned repos
python extract.py

# 2. Generate synthetic Q&A (needs local LLM on port 8080)
python synthesize.py

# 3. Deduplicate and quality filter
python dedup.py
```

Edit the `BASE` path at the top of each script to point to your working directory.

### Evaluation

```bash
cd eval
pip install -r requirements.txt

# Run eval against any OpenAI-compatible model endpoint
python eval.py \
  --model-url http://localhost:8080/v1 \
  --model-name your-model-name \
  --tag my_run

# Compare two runs
python eval.py --compare results/run_a_results.json results/run_b_results.json
```

### Prerequisites for Compilation Checks

```bash
# Rust + nightly (for aya kernel programs)
rustup install nightly
rustup target add bpfel-unknown-none

# Go >= 1.22 (for cilium/ebpf programs)

# Clang + libbpf headers (for C programs)
apt install clang libbpf-dev linux-headers-$(uname -r)

# Pre-build template dependencies once (speeds up eval from ~90s to ~5s per check)
cd eval/templates/aya_kernel && cargo +nightly check -Z build-std=core --target bpfel-unknown-none
cd eval/templates/aya_user && cargo check
cd eval/templates/cilium_go && go mod tidy

# Generate vmlinux.h for your kernel (for libbpf C checks)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > eval/templates/libbpf_c/vmlinux.h
```

> **Note:** `vmlinux.h` is not included in the repo (kernel-version specific). Generate it with the command above.

## Training

Fine-tuning was done with [Unsloth Studio](https://github.com/unslothai/unsloth).

**LoRA config (Qwen3.5-4B, v2 dataset):**
- Epochs: 3, Context: 2048
- Rank: 32, Alpha: 32, Dropout: 0
- Target modules: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj
- Optimizer: AdamW 8-bit, LR scheduler: cosine
- Learning rate: 2e-4, Warmup steps: 100
- Batch size: 4, Gradient accumulation: 4 (effective batch: 16)

See [docs/blog_post.md](docs/blog_post.md) for the full write-up.
