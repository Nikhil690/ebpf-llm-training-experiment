# Dataset Construction

## Overview

The dataset was built in three stages: extraction from open-source repos, synthetic Q&A generation, and deduplication/quality filtering.

Final dataset: **10,000 samples** in ShareGPT format
HuggingFace: [Nikhil69/ebpf-instruct](https://huggingface.co/datasets/Nikhil69/ebpf-instruct)

---

## Stage 1: Extraction (`extract.py`)

### Source Repositories

| Repo | Language | Focus |
|---|---|---|
| aya-rs/aya | Rust | aya kernel + user-space framework |
| libbpf/libbpf | C | core libbpf library |
| libbpf/libbpf-bootstrap | C | libbpf examples |
| libbpf/libbpf-rs | Rust | Rust bindings for libbpf |
| cilium/ebpf | Go | cilium/ebpf Go library |
| cilium/tetragon | Go/C | eBPF-based security tool |
| aquasecurity/tracee | Go/C | runtime security |
| iovisor/bcc | Python/C | BCC toolkit |
| grafana/beyla | Go | eBPF auto-instrumentation |
| deepflowio/deepflow | Go/C | observability platform |
| redbpf | Rust | Rust eBPF framework |
| bpfman | Rust | eBPF program manager |
| retis | Rust | network tracing |
| ebpf-docs | Markdown | eBPF specification docs |
| bpf-developer-tutorial | C/Markdown | libbpf tutorials |
| learning-ebpf | Python/C | book code samples |
| bpf-perf-tools-book | C | BPF performance tools |
| linux-bpf-docs | RST | kernel BPF documentation |
| eunomia-bpf | C/Rust | eBPF development tools |

### File Types Extracted

- `.rs` — Rust source (aya kernel programs, user-space code)
- `.c` / `.h` — C source (libbpf programs, BCC)
- `.go` — Go source (cilium/ebpf programs)
- `.py` — Python source (BCC programs)
- `.md` — Markdown documentation
- `.rst` — ReStructuredText (kernel docs)

### Filters Applied

Noise reduction:
- Skip known non-content files: `CODE_OF_CONDUCT`, `CHANGELOG`, `LICENSE`, `CONTRIBUTING`, `SECURITY`
- Markdown files must contain eBPF signal words: `ebpf`, `bpf`, `xdp`, `kprobe`, `tracepoint`, `perf_event`, `map`, `libbpf`, `aya`, `cilium`
- Minimum chunk length: 50 characters

Output: **17,887 chunks** in `chunks.jsonl`

---

## Stage 2: Synthesis (`synthesize.py`)

### Model

Local Qwen3-Coder-79B (Q6_K GGUF) via llama-server OpenAI-compatible API at `http://localhost:8080/v1`.

Server configuration for throughput:
```bash
llama-server -m model.gguf \
  --parallel 8 \
  --ngl 80 \
  --flash-attn on \
  --ctx-size 32768
```

### Generation Styles

Each chunk is classified and prompted with a matching style:

| Style | Temperature | Description |
|---|---|---|
| `code_completion` | 0.3 | Complete or implement this eBPF program |
| `explain` | 0.6 | Explain what this code does |
| `debug` | 0.4 | Find and fix the bug |
| `design` | 0.7 | How would you design/implement X |
| `compare` | 0.6 | Compare two approaches |
| `concept` | 0.7 | Explain the concept |

### Performance

- 12 ThreadPoolExecutor workers
- ~5-8 samples/min with `--parallel 8 --ngl 80`
- Resume support: tracks completed chunk IDs, skips on restart
- Max 768 tokens per answer

Output: **19,048 samples** in `synthetic.jsonl`

---

## Stage 3: Deduplication (`dedup.py`)

### Quality Filters

```python
MIN_ANSWER_CHARS = 150
MIN_ANSWER_WORDS = 30
```

- Must contain at least one eBPF signal word in the answer
- Answer must not be a refusal ("I cannot", "I don't know")

### Exact Deduplication

MD5 hash of:
1. `question + answer` (exact duplicate pair)
2. `question` alone (same question, different answers)

### Near-Deduplication

MinHash LSH:
- 128 hash functions
- Jaccard similarity threshold: 0.85
- 64 parallel workers

Removes semantically similar samples that differ only in variable names or minor rewording.

### Results

```
Input:  19,048 samples
After quality filter: ~14,000
After exact dedup:    ~12,500
After near-dedup:     10,000
```

---

## Dataset Format

ShareGPT format, compatible with Unsloth, Axolotl, LLaMA-Factory:

```json
{
  "conversations": [
    {
      "from": "system",
      "value": "You are an expert eBPF developer..."
    },
    {
      "from": "human",
      "value": "Write an eBPF XDP program that counts packets per source IP..."
    },
    {
      "from": "gpt",
      "value": "#include \"vmlinux.h\"\n#include <bpf/bpf_helpers.h>..."
    }
  ]
}
```

## Category Distribution (approximate)

- libbpf C programs: ~30%
- aya Rust (kernel + user): ~20%
- cilium/ebpf Go: ~20%
- BCC Python: ~10%
- Conceptual/explanation: ~20%
