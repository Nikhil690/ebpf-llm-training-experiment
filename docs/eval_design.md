# eBPF-HumanEval: Evaluation Design

## Philosophy

Keyword matching is not enough for code evaluation. A response that mentions "XDP", "BPF_MAP_TYPE_HASH", and "bpf_helpers.h" may still be completely non-functional. This benchmark uses **compilation as the ground truth**.

Pass@1: the model's output must compile without errors on the first attempt.

---

## Problem Set

40 problems across 5 categories (`eval/problems.jsonl`):

| Category | Count | Difficulty |
|---|---|---|
| aya_kernel | 10 | hard (nightly Rust, no_std, BPF target) |
| aya_user | 4 | medium (async Rust, aya user-space API) |
| cilium_go | 10 | medium (Go, cilium/ebpf v0.17) |
| libbpf_c | 10 | medium (C, CO-RE, vmlinux.h) |
| conceptual | 6 | easy (keyword coverage) |

Problem format:

```json
{
  "id": "c_025",
  "category": "libbpf_c",
  "difficulty": "medium",
  "check": "compile",
  "prompt": "Write an XDP program using CO-RE...",
  "keywords": []
}
```

---

## Check Methods

### aya_kernel

Requires nightly Rust and the `bpfel-unknown-none` target (bare-metal BPF VM, no std).

```bash
cargo +nightly check \
  -Z build-std=core \
  --target bpfel-unknown-none \
  --target-dir <shared_cache> \
  --message-format short
```

Template: `eval/templates/aya_kernel/`
- `Cargo.toml`: deps on `aya-ebpf`, `aya-log-ebpf`
- `.cargo/config.toml`: sets default target and build-std
- Pre-built target dir: reused across all checks (5s vs 90s cold)

### aya_user

Standard Rust compilation checking aya user-space code.

```bash
cargo check \
  --target-dir <shared_cache> \
  --message-format short
```

Template: `eval/templates/aya_user/`
- `Cargo.toml`: deps on `aya`, `aya-log`, `tokio`, `anyhow`

### cilium_go

```bash
go mod tidy   # resolve any packages the model imports
go build ./...
```

Template: `eval/templates/cilium_go/`
- `go.mod`: `github.com/cilium/ebpf v0.17.3`
- `go.sum`: pre-generated (avoids network calls per check)

### libbpf_c

```bash
clang -target bpf \
  -O2 -g \
  -I{tmp_dir} \          # picks up vmlinux.h
  -I/usr/include/bpf \   # bpf_helpers.h
  -I/usr/include/linux \
  -c prog.bpf.c \
  -o prog.o
```

`vmlinux.h` is generated from the running kernel:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > templates/libbpf_c/vmlinux.h
```

This single header (205k lines) provides all kernel struct definitions for CO-RE programs without needing kernel headers.

All C prompts specify: `Use CO-RE style with #include "vmlinux.h" and #include <bpf/bpf_helpers.h> only`

### conceptual

Keyword coverage check: the answer must contain at least 50% of the expected keywords (case-insensitive). Minimum 3 keywords required.

```python
required = max(3, len(keywords) // 2)
passed = len(found) >= required
```

---

## Performance Optimizations

### Shared Cargo Target Directories

The biggest bottleneck was Cargo proc-macro compilation. Each cold `cargo check` compiles aya's proc-macros from scratch: ~90 seconds.

Fix: pre-build template project once, pass `--target-dir` pointing to that pre-built directory. Subsequent checks find cached proc-macros and complete in 5-10s.

```
eval/templates/aya_kernel/target/   <- pre-built, shared across all checks
eval/templates/aya_user/target/     <- same
```

### Pre-warmed Go Module Cache

`go mod tidy` downloads modules on first run. Pre-generate `go.sum` in the template and copy it to the temp dir before each check. This avoids network calls during evaluation.

---

## Running the Benchmark

```bash
cd eval
uv init && uv add openai tqdm

python eval.py \
  --model-url http://localhost:8080/v1 \
  --model-name "your-model" \
  --tag baseline \
  --problems problems.jsonl

# Filter to one category
python eval.py --category libbpf_c ...

# Compare two runs
python eval.py \
  --compare results/baseline_results.json results/finetuned_results.json
```

---

## Known Limitations

1. **aya stays at 0%** across all tested models — Rust eBPF is underrepresented in both pretraining and our fine-tuning data. The proc-macro system (`#[map]`, `#[xdp]`) is especially tricky.

2. **40 problems is a thin benchmark** — individual problem variance is high. A single problem passing/failing can move the score by 2.5%.

3. **Pass@1 only** — we measure single-shot correctness. Pass@k (run k times, pass if any attempt succeeds) would give a more robust signal.

4. **No semantic correctness** — compilation passing doesn't mean the program does what was asked. An XDP program that always returns `XDP_DROP` compiles but is wrong.

5. **vmlinux.h is kernel-version specific** — generated from the test machine's kernel. Some BTF types may differ on other kernel versions.
