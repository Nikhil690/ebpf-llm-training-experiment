# eBPF-HumanEval Results

All evaluations use the same 40-problem eBPF-HumanEval benchmark with compilation-based pass@1.

Eval script: `eval/eval.py`

---

## Summary

| Model | Overall | aya_kernel | aya_user | cilium_go | libbpf_c | conceptual |
|---|---|---|---|---|---|---|
| Qwen3.5-4B baseline | 12.5% (5/40) | 0/10 | 0/4 | 0/10 | 0/10 | 5/6 |
| **Qwen3.5-4B fine-tuned (v2)** | **22.5% (9/40)** | **0/10** | **0/4** | **0/10** | **3/10** | **6/6** |

Fine-tuning improvement: **+10pp absolute, +80% relative**

---

## Qwen3.5-4B Baseline (tag: qwen_baseline_v2)

```
Overall pass@1 : 5/40 (12.5%)

aya_kernel     0/10  (0%)
aya_user       0/4   (0%)
cilium_go      0/10  (0%)
conceptual     5/6   (83%)
libbpf_c       0/10  (0%)
```

Key failure patterns:
- `aya_kernel`: wrong imports (`aya::*` instead of `aya_ebpf::*`), missing `#![no_std]`
- `cilium_go`: hallucinated `github.com/cilium/ebpf/bpf` package (doesn't exist)
- `libbpf_c`: missing `SEC()` macros, wrong map definition syntax

---

## Qwen3.5-4B Fine-tuned v2 (tag: qwen_ft_v2_f16)

Dataset: `ebpf-instruct-v2` (6,412 samples, 3 epochs, rank 32 LoRA)

```
Overall pass@1 : 9/40 (22.5%)

aya_kernel     0/10  (0%)
aya_user       0/4   (0%)
cilium_go      0/10  (0%)
conceptual     6/6   (100%)
libbpf_c       3/10  (30%)
```

Improvements over baseline:
- `conceptual`: 5/6 → 6/6 (+1)
- `libbpf_c`: 0/10 → 3/10 (+3) — model learned CO-RE style, correct map definitions
- `cilium_go` still 0/10 — model uses `rlimit.RemoveMemlock()` correctly but misses the import
- `aya_kernel` still 0/10 — `#[map]` attribute import path issues persist

Remaining libbpf_c failures:
- `bpf_htons` / `ETH_P_IP` undeclared (model uses them correctly but omits `<bpf/bpf_endian.h>`)
- `TC_ACT_SHOT` undeclared (model uses TC correctly but omits `<linux/pkt_cls.h>`)
- BPF_KPROBE argument syntax errors on complex signatures

---

## Analysis

The fine-tuned model shows clear improvement in areas well-represented in the training data:
- **libbpf C** improved most (+30pp) — strong CO-RE style signal in the v2 dataset
- **Conceptual** reached 100% — eBPF-specific explanations are well-learned
- **aya and cilium/ebpf** need more targeted training examples in a future v3 dataset

The dataset v2 improvements (eBPF signal filters removing non-eBPF code) produced cleaner training signal compared to v1, which directly contributed to the libbpf_c gains.
