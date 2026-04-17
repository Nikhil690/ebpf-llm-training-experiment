# eBPF-HumanEval Results

All evaluations use the same 40-problem eBPF-HumanEval benchmark with compilation-based pass@1.

Eval script: `eval/eval.py`

---

## Summary

| Model | Params | Overall | aya_kernel | aya_user | cilium_go | libbpf_c | conceptual |
|---|---|---|---|---|---|---|---|
| Qwen3.5-4B baseline | 4B | 12.5% (5/40) | 0/10 | 0/4 | 0/10 | 0/10 | 5/6 |
| Qwen3.5-4B fine-tuned (v2) | 4B | 22.5% (9/40) | 0/10 | 0/4 | 0/10 | 3/10 | 6/6 |
| Gemma-4-31B baseline | 31B | 35.0% (14/40) | 0/10 | 0/4 | 2/10 | 6/10 | 6/6 |
| Gemma-4-31B fine-tuned | 31B | 35.0% (14/40) | 0/10 | 0/4 | 3/10 | 5/10 | 6/6 |

Qwen3.5-4B fine-tuning improvement: **+10pp absolute, +80% relative**  
Gemma-4-31B fine-tuning improvement: **0pp** — fine-tuning did not help the larger model

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

## Gemma-4-31B Baseline (tag: gemma_baseline_final)

```
Overall pass@1 : 14/40 (35.0%)

aya_kernel     0/10  (0%)
aya_user       0/4   (0%)
cilium_go      2/10  (20%)
conceptual     6/6   (100%)
libbpf_c       6/10  (60%)
```

Strong baseline from the larger model — libbpf C at 60% without any fine-tuning. Still 0% on aya
(same failure modes as Qwen: proc-macro attribute confusion). cilium_go passes 2 problems at baseline.

Key failure patterns:
- `aya_kernel`: timeout/hang on most problems — model generates non-compilable Rust
- `aya_user`: deprecated `aya::Bpf` type alias, missing `main` function
- `cilium_go`: hallucinated API fields (`ebpf.Uint32`, `m.Range`), wrong argument counts

---

## Gemma-4-31B Fine-tuned (tag: gemma_finetuned_final)

Dataset: `ebpf-instruct-v2` (6,412 samples, same v2 dataset as Qwen fine-tune)

```
Overall pass@1 : 14/40 (35.0%)

aya_kernel     0/10  (0%)
aya_user       0/4   (0%)
cilium_go      3/10  (30%)
conceptual     6/6   (100%)
libbpf_c       5/10  (50%)
```

No improvement overall (+0pp). Mixed category shifts:
- `cilium_go`: 2/10 → 3/10 (+1)
- `libbpf_c`: 6/10 → 5/10 (-1) — regression, model introduced incorrect CO-RE patterns
- Fine-tuning on the v2 dataset (optimized for a 4B model) did not benefit the 31B model

---

## Analysis

The fine-tuned model shows clear improvement in areas well-represented in the training data:
- **libbpf C** improved most (+30pp for Qwen) — strong CO-RE style signal in the v2 dataset
- **Conceptual** reached 100% — eBPF-specific explanations are well-learned
- **aya and cilium/ebpf** need more targeted training examples in a future v3 dataset

The dataset v2 improvements (eBPF signal filters removing non-eBPF code) produced cleaner training signal compared to v1, which directly contributed to the libbpf_c gains.

**Gemma fine-tuning result:** Fine-tuning a 31B model on a 6,412-sample dataset optimized around a 4B model's failure modes did not yield improvement. The larger model's baseline is already higher, and the synthetic data may not be challenging enough to shift its weights meaningfully. A targeted dataset for aya/cilium_go failures would be needed to move the needle.
