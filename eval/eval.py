"""
eBPF-HumanEval: Evaluation framework for eBPF coding models.

Usage:
  python eval.py --model-url http://localhost:8080/v1 \
                 --model-name qwen3.5:27b \
                 --tag baseline \
                 --problems problems.jsonl

Outputs: results/<tag>_results.json + results/<tag>_report.txt

Check types:
  compile       — cargo check (aya user-space)
  compile_bpf   — clang -target bpf (C libbpf kernel programs)
  aya_kernel    — cargo check --target bpfel-unknown-none
  keywords      — check answer contains expected technical keywords
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from openai import OpenAI
from tqdm import tqdm

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

BASE        = Path(__file__).parent
TEMPLATES   = BASE / "templates"
RESULTS_DIR = BASE / "results"
RESULTS_DIR.mkdir(exist_ok=True)

SYSTEM_PROMPT = """\
You are an expert eBPF developer with deep knowledge of:
- aya Rust eBPF framework (kernel-side and user-space)
- cilium/ebpf Go library
- libbpf C framework
- eBPF maps, programs, BTF, CO-RE, verifier rules

For coding tasks: output ONLY the complete code with no explanation. Do not add markdown code fences. Output raw code only.
For conceptual/explanation tasks: answer clearly and directly in plain text."""

COMPILE_TIMEOUT = 90  # seconds per compilation

# ──────────────────────────────────────────────
# Model query
# ──────────────────────────────────────────────

def query_model(client: OpenAI, model: str, prompt: str) -> tuple[str, float]:
    start = time.time()
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,   # low temp for eval — want deterministic code
            max_tokens=4096,
        )
        answer = resp.choices[0].message.content.strip()
        # Strip think tags if present (handles models that ignore enable_thinking)
        answer = re.sub(r"<think>.*?</think>", "", answer, flags=re.DOTALL).strip()
        # Strip markdown fences if model ignores instructions
        answer = re.sub(r"^```\w*\n?", "", answer)
        answer = re.sub(r"\n?```$", "", answer)
        elapsed = time.time() - start
        return answer.strip(), elapsed
    except Exception as e:
        return f"ERROR: {e}", time.time() - start


# ──────────────────────────────────────────────
# Compilation checks
# ──────────────────────────────────────────────

def check_aya_kernel(code: str) -> tuple[bool, str]:
    """cargo +nightly check using shared pre-compiled target dir."""
    template  = TEMPLATES / "aya_kernel"
    target_dir = template / "target"
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        src.mkdir()
        shutil.copy(template / "Cargo.toml", tmp)
        shutil.copytree(template / ".cargo", Path(tmp) / ".cargo")
        if (template / "Cargo.lock").exists():
            shutil.copy(template / "Cargo.lock", tmp)
        (src / "main.rs").write_text(code)
        result = subprocess.run(
            ["cargo", "+nightly", "check",
             "-Z", "build-std=core",
             "--target", "bpfel-unknown-none",
             "--target-dir", str(target_dir),
             "--message-format", "short"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT * 2,
        )
        if result.returncode == 0:
            return True, ""
        errors = (result.stdout + result.stderr)[:600]
        # Filter out the known harmless panic_handler error that comes from
        # incomplete template code — only flag if there are OTHER errors too
        if "panic_handler" in errors and errors.count("error") <= 2:
            return False, errors
        return False, errors


def check_aya_user(code: str) -> tuple[bool, str]:
    """cargo check reusing pre-compiled target dir."""
    template   = TEMPLATES / "aya_user"
    target_dir = template / "target"
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        src.mkdir()
        shutil.copy(template / "Cargo.toml", tmp)
        if (template / "Cargo.lock").exists():
            shutil.copy(template / "Cargo.lock", tmp)
        (src / "main.rs").write_text(code)
        result = subprocess.run(
            ["cargo", "check",
             "--target-dir", str(target_dir),
             "--message-format", "short"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        if result.returncode == 0:
            return True, ""
        return False, (result.stdout + result.stderr)[:600]


def check_cilium_go(code: str) -> tuple[bool, str]:
    """go build — uses pre-warmed template with go.sum"""
    with tempfile.TemporaryDirectory() as tmp:
        # Copy pre-warmed template (includes go.sum)
        for f in ["go.mod", "go.sum"]:
            src = TEMPLATES / "cilium_go" / f
            if src.exists():
                shutil.copy(src, tmp)
        (Path(tmp) / "main.go").write_text(code)
        # tidy to resolve any valid sub-packages the model imports
        subprocess.run(["go", "mod", "tidy"], cwd=tmp,
                       capture_output=True, timeout=60)
        result = subprocess.run(
            ["go", "build", "./..."],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        if result.returncode == 0:
            return True, ""
        return False, (result.stdout + result.stderr)[:600]


def check_libbpf_c(code: str) -> tuple[bool, str]:
    """clang -target bpf using vmlinux.h for CO-RE style includes"""
    with tempfile.TemporaryDirectory() as tmp:
        # Copy vmlinux.h into tmp so model can #include it
        vmlinux = TEMPLATES / "libbpf_c" / "vmlinux.h"
        if vmlinux.exists():
            shutil.copy(vmlinux, tmp)
        src = Path(tmp) / "prog.bpf.c"
        src.write_text(code)
        result = subprocess.run(
            [
                "clang", "-target", "bpf",
                "-O2", "-g",
                f"-I{tmp}",                          # picks up vmlinux.h
                "-I/usr/include/bpf",                # bpf_helpers.h etc.
                "-I/usr/include/linux",
                "-I/usr/include/aarch64-linux-gnu",
                "-c", str(src),
                "-o", str(Path(tmp) / "prog.o"),
            ],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        if result.returncode == 0:
            return True, ""
        return False, (result.stdout + result.stderr)[:600]


def check_keywords(answer: str, keywords: list[str]) -> tuple[bool, str]:
    """Check answer contains minimum required eBPF keywords."""
    answer_lower = answer.lower()
    found    = [k for k in keywords if k.lower() in answer_lower]
    missing  = [k for k in keywords if k.lower() not in answer_lower]
    required = max(3, len(keywords) // 2)   # need at least half
    passed   = len(found) >= required
    detail   = f"Found {len(found)}/{len(keywords)} keywords. Missing: {missing[:5]}"
    return passed, detail


# ──────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────

def run_check(problem: dict, answer: str) -> tuple[bool, str]:
    check = problem["check"]
    cat   = problem["category"]

    if check == "keywords":
        return check_keywords(answer, problem.get("keywords", []))

    try:
        if cat == "aya_kernel":
            return check_aya_kernel(answer)
        elif cat == "aya_user":
            return check_aya_user(answer)
        elif cat == "cilium_go":
            return check_cilium_go(answer)
        elif cat == "libbpf_c":
            return check_libbpf_c(answer)
        else:
            return False, f"Unknown category: {cat}"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT: compilation exceeded limit"
    except Exception as e:
        return False, f"ERROR: {e}"


# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def generate_report(results: list[dict], tag: str, model: str) -> str:
    total    = len(results)
    passed   = sum(1 for r in results if r["passed"])
    pass_at1 = passed / total * 100

    by_cat: dict[str, list] = {}
    for r in results:
        by_cat.setdefault(r["category"], []).append(r["passed"])

    lines = [
        f"eBPF-HumanEval Results",
        f"=" * 50,
        f"Model  : {model}",
        f"Tag    : {tag}",
        f"",
        f"Overall pass@1 : {passed}/{total} ({pass_at1:.1f}%)",
        f"",
        f"By category:",
    ]
    for cat, outcomes in sorted(by_cat.items()):
        p = sum(outcomes)
        n = len(outcomes)
        lines.append(f"  {cat:<20} {p}/{n}  ({p/n*100:.0f}%)")

    lines += ["", "Per-problem results:"]
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(f"  [{status}] {r['id']:<15} ({r['category']}) {r['latency_s']:.1f}s")
        if not r["passed"] and r["error"]:
            lines.append(f"         ↳ {r['error'][:120]}")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Compare two result files
# ──────────────────────────────────────────────

def compare_results(file_a: Path, file_b: Path):
    with open(file_a) as f:
        a = {r["id"]: r for r in json.load(f)["results"]}
    with open(file_b) as f:
        b = {r["id"]: r for r in json.load(f)["results"]}

    tag_a = json.load(open(file_a))["tag"]
    tag_b = json.load(open(file_b))["tag"]

    print(f"\nComparison: {tag_a} vs {tag_b}")
    print("=" * 60)

    same_pass = improved = regressed = 0
    for pid in sorted(a):
        pa = a[pid]["passed"]
        pb = b[pid]["passed"] if pid in b else False
        if pa == pb:
            same_pass += 1
        elif not pa and pb:
            improved += 1
            print(f"  IMPROVED : {pid}")
        elif pa and not pb:
            regressed += 1
            print(f"  REGRESSED: {pid}")

    total = len(a)
    print(f"\n{tag_a} pass@1: {sum(r['passed'] for r in a.values())}/{total}")
    print(f"{tag_b} pass@1: {sum(r['passed'] for r in b.values())}/{total}")
    print(f"Improved  : {improved}")
    print(f"Regressed : {regressed}")
    print(f"Unchanged : {same_pass}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="eBPF-HumanEval")
    parser.add_argument("--model-url",   default="http://localhost:8080/v1")
    parser.add_argument("--model-name",  default="qwen3.5:27b")
    parser.add_argument("--tag",         required=True, help="e.g. baseline or finetuned")
    parser.add_argument("--problems",    default=str(BASE / "problems.jsonl"))
    parser.add_argument("--compare",     nargs=2, metavar=("FILE_A", "FILE_B"),
                        help="Compare two result JSON files instead of running eval")
    parser.add_argument("--category",    help="Only run problems from this category")
    args = parser.parse_args()

    if args.compare:
        compare_results(Path(args.compare[0]), Path(args.compare[1]))
        return

    # Load problems
    problems = []
    with open(args.problems) as f:
        for line in f:
            p = json.loads(line.strip())
            if args.category and p["category"] != args.category:
                continue
            problems.append(p)

    print(f"eBPF-HumanEval")
    print(f"Model   : {args.model_name}  @  {args.model_url}")
    print(f"Tag     : {args.tag}")
    print(f"Problems: {len(problems)}\n")

    client  = OpenAI(base_url=args.model_url, api_key="not-needed")
    results = []

    for prob in tqdm(problems, desc="Evaluating"):
        answer, latency = query_model(client, args.model_name, prob["prompt"])
        passed, error   = run_check(prob, answer)

        results.append({
            "id":        prob["id"],
            "category":  prob["category"],
            "difficulty": prob["difficulty"],
            "passed":    passed,
            "error":     error,
            "latency_s": round(latency, 2),
            "answer":    answer[:2000],   # truncate for storage
        })

        status = "✓" if passed else "✗"
        tqdm.write(f"  {status} {prob['id']:<15} {latency:.1f}s  {error[:60] if error else ''}")

    # Save JSON
    out_json = RESULTS_DIR / f"{args.tag}_results.json"
    with open(out_json, "w") as f:
        json.dump({
            "tag": args.tag, "model": args.model_name,
            "total": len(results),
            "passed": sum(r["passed"] for r in results),
            "results": results,
        }, f, indent=2)

    # Save report
    report = generate_report(results, args.tag, args.model_name)
    out_txt = RESULTS_DIR / f"{args.tag}_report.txt"
    out_txt.write_text(report)

    print(f"\n{report}")
    print(f"\nSaved: {out_json}")
    print(f"Saved: {out_txt}")


if __name__ == "__main__":
    main()
