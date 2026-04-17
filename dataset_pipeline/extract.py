"""
Phase 1: Extract raw eBPF knowledge chunks from all source repos.

Produces: dataset_raw/chunks.jsonl
Each line: {"id", "source", "repo", "file", "lang", "kind", "title", "body", "code"}

kind:
  - tutorial_section  : markdown section with optional embedded code
  - doc_code          : source file function/struct with doc-comment
  - raw_code          : source file without doc-comment (code only)
"""

import json
import re
import hashlib
import multiprocessing as mp
from pathlib import Path
from tqdm import tqdm

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

BASE = Path("/data/First_Dataset")
OUT  = BASE / "dataset_raw" / "chunks.jsonl"

REPOS = {
    # repo_dir            : (languages_to_scan,  include_md)
    "aya"                 : (["rs"],              True),
    "book"                : (["rs"],              True),
    "bpf-developer-tutorial": (["c", "rs", "py"], True),
    "bcc"                 : (["c", "py"],          True),
    "beyla"               : (["go"],              True),
    "bpfman"              : (["rs", "c", "go"],   True),
    "bpf-perf-tools-book" : ([],                  True),
    "deepflow"            : (["go", "c"],          False),
    "ebpf"                : (["go", "c"],          True),
    "eunomia-bpf"         : (["rs", "c"],          True),
    "learning-ebpf"       : (["c", "py"],          True),
    "libbpf-bootstrap"    : (["c"],               True),
    "libbpf-rs"           : (["rs", "c"],          True),
    "redbpf"              : (["rs"],              False),
    "retis"               : (["rs", "c"],          True),
    "tetragon"            : (["go", "c"],          True),
    "tracee"              : (["go", "c"],          True),
    # Theoretical / reference sources
    "linux-bpf-docs"      : (["c", "h"],          False),  # RST handled separately
    "libbpf"              : (["c", "h"],          False),
}

# Skip paths that are generated / vendored / test noise
SKIP_DIRS = {
    "vendor", "node_modules", ".git", "target", "__pycache__",
    "testdata", "fixtures", "third_party", "proto", "generated",
    "_build", "dist", "build",
}

# Skip markdown files by name — non-technical content
SKIP_MD_NAMES = {
    "agents", "agents_notes", "code_of_conduct", "contributing",
    "changelog", "security", "governance", "maintainers", "codeowners",
    "release", "authors", "license", "brewfile", "summary",
    "readme",   # bare README with no tutorial content — filtered by MIN_BODY_CHARS anyway
}

# Markdown must contain at least one of these signals to be kept
MD_SIGNAL_WORDS = re.compile(
    r"\bebpf\b|\bbpf\b|\bxdp\b|\bkprobe\b|\btracepoint\b|\blsm\b|"
    r"\baya\b|\blibbpf\b|\bcilium\b|\bbcc\b|\bmap\b|\bprogram\b|"
    r"\bsyscall\b|\bkernel\b|\bverifier\b|\bbtf\b|\bco-re\b|"
    r"\bring.buffer\b|\bperf.event\b|\bsocket\b|\btc\b|\bcgroup\b",
    re.IGNORECASE,
)

# Minimum content size to be worth keeping
MIN_BODY_CHARS  = 80
MIN_CODE_CHARS  = 30

# eBPF signal patterns — a source file must contain at least one to be included
# This filters out userspace utilities, test harnesses, and build scripts
BPF_C_SIGNALS = re.compile(
    r'\bSEC\s*\(|BPF_PROG\b|BPF_MAP_TYPE_|bpf_helpers\.h|vmlinux\.h|'
    r'bpf_map_def\b|struct\s+xdp_md\b|struct\s+__sk_buff\b|'
    r'bpf_printk\b|bpf_probe_read|bpf_get_current|BPF_KPROBE\b|'
    r'BPF_TRACEPOINT\b|BPF_XDP\b|BPF_TC\b|BPF_LSM\b|'
    r'bpf_map_lookup_elem|bpf_map_update_elem|LIBBPF_OPTS\b'
)

BPF_RUST_SIGNALS = re.compile(
    r'#\[xdp\]|#\[kprobe\]|#\[map\]|#\[tracepoint\]|#\[lsm\]|'
    r'#\[uprobe\]|#\[tc\]|#\[cgroup_skb\]|#\[sock_ops\]|'
    r'aya_ebpf|aya-ebpf|use aya::|EbpfLoader|Bpf::load'
)

BPF_GO_SIGNALS = re.compile(
    r'cilium/ebpf|ebpf\.LoadCollection|ebpf\.NewMap|link\.AttachXDP|'
    r'link\.AttachTracepoint|link\.AttachKprobe|ebpf\.LoadPinnedMap|'
    r'bpf2go|NewReader\b.*ringbuf|perf\.NewReader'
)

# Max markdown section size (chars) — split if larger
MAX_SECTION_CHARS = 4000

WORKERS = min(64, mp.cpu_count())

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def make_id(repo: str, path: str, extra: str = "") -> str:
    h = hashlib.sha1(f"{repo}:{path}:{extra}".encode()).hexdigest()[:12]
    return h


def should_skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    # Skip non-technical markdown files by filename stem
    if path.suffix.lower() == ".md":
        stem = path.stem.lower().replace("-", "_")
        if stem in SKIP_MD_NAMES:
            return True
    return False


# ──────────────────────────────────────────────
# Markdown extraction
# ──────────────────────────────────────────────

_CODE_BLOCK = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
_HEADING    = re.compile(r"^(#{1,4})\s+(.+)$", re.MULTILINE)


def extract_code_blocks(text: str) -> list[dict]:
    blocks = []
    for m in _CODE_BLOCK.finditer(text):
        lang = m.group(1).strip().lower() or "text"
        code = m.group(2).strip()
        if len(code) >= MIN_CODE_CHARS:
            blocks.append({"lang": lang, "code": code})
    return blocks


def split_markdown(text: str, max_chars: int = MAX_SECTION_CHARS) -> list[str]:
    """Split oversized sections into ~max_chars chunks at paragraph boundaries."""
    if len(text) <= max_chars:
        return [text]
    parts, current = [], []
    length = 0
    for para in text.split("\n\n"):
        if length + len(para) > max_chars and current:
            parts.append("\n\n".join(current))
            current, length = [], 0
        current.append(para)
        length += len(para)
    if current:
        parts.append("\n\n".join(current))
    return parts


def process_markdown(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    # Drop markdown files with no eBPF-related content at all
    if not MD_SIGNAL_WORDS.search(text):
        return []

    chunks = []
    headings = list(_HEADING.finditer(text))

    if not headings:
        # No headings — treat whole file as one section
        code_blocks = extract_code_blocks(text)
        body = _CODE_BLOCK.sub("", text).strip()
        if len(body) >= MIN_BODY_CHARS or code_blocks:
            for i, part in enumerate(split_markdown(body)):
                chunks.append({
                    "id":     make_id(repo, str(path), f"full_{i}"),
                    "source": "markdown",
                    "repo":   repo,
                    "file":   str(path.relative_to(BASE)),
                    "lang":   "text",
                    "kind":   "tutorial_section",
                    "title":  path.stem.replace("-", " ").replace("_", " ").title(),
                    "body":   part,
                    "code":   [b["code"] for b in code_blocks[:3]],
                })
        return chunks

    for idx, m in enumerate(headings):
        start = m.end()
        end   = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
        section_text = text[start:end].strip()
        code_blocks  = extract_code_blocks(section_text)
        body         = _CODE_BLOCK.sub("", section_text).strip()

        if len(body) < MIN_BODY_CHARS and not code_blocks:
            continue

        title = m.group(2).strip()
        for i, part in enumerate(split_markdown(body)):
            chunks.append({
                "id":     make_id(repo, str(path), f"{title}_{i}"),
                "source": "markdown",
                "repo":   repo,
                "file":   str(path.relative_to(BASE)),
                "lang":   "text",
                "kind":   "tutorial_section",
                "title":  title,
                "body":   part,
                "code":   [b["code"] for b in code_blocks[:4]],
            })

    return chunks


# ──────────────────────────────────────────────
# Rust extraction
# ──────────────────────────────────────────────

_RS_DOC_FN = re.compile(
    r"((?:///[^\n]*\n)+)"          # doc comment block
    r"[ \t]*(?:#\[.*?\]\n)*"       # optional attributes
    r"[ \t]*(pub(?:\([^)]*\))?\s+)?"
    r"((?:async\s+)?fn\s+\w+[^{]*\{)",
    re.DOTALL,
)

_RS_IMPL_BLOCK = re.compile(
    r"((?:///[^\n]*\n)+)"
    r"[ \t]*(pub(?:\([^)]*\))?\s+)?"
    r"((?:struct|enum|impl|trait)\s+\w+[^{]*\{)",
    re.DOTALL,
)

_RS_BARE_FN = re.compile(
    r"^[ \t]*(pub(?:\([^)]*\))?\s+)?fn\s+(\w+)\s*\(",
    re.MULTILINE,
)


def extract_rs_body(text: str, start: int) -> str:
    """Extract the body of a Rust item starting at `start` (the opening `{`)."""
    depth, i, limit = 0, start, min(start + 2000, len(text))
    while i < limit:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return text[start : start + 600]


def clean_doc(doc: str) -> str:
    return "\n".join(
        line.lstrip("/").lstrip() for line in doc.splitlines()
    ).strip()


def process_rust(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    # Only include Rust files that are actual eBPF programs or aya API usage
    if not BPF_RUST_SIGNALS.search(text):
        return []

    chunks = []
    seen = set()

    for pattern in (_RS_DOC_FN, _RS_IMPL_BLOCK):
        for m in pattern.finditer(text):
            doc   = clean_doc(m.group(1))
            decl  = m.group(3).strip()
            name  = re.search(r"\b(\w+)\s*[({<]", decl)
            name  = name.group(1) if name else decl[:40]
            body  = extract_rs_body(text, m.end() - 1)
            code  = (decl + "\n" + body).strip()

            if len(code) < MIN_CODE_CHARS or name in seen:
                continue
            seen.add(name)

            chunks.append({
                "id":     make_id(repo, str(path), name),
                "source": "source",
                "repo":   repo,
                "file":   str(path.relative_to(BASE)),
                "lang":   "rust",
                "kind":   "doc_code",
                "title":  name,
                "body":   doc,
                "code":   [code],
            })

    # Also grab functions WITHOUT doc comments — still useful as raw code
    if len(chunks) == 0:
        for m in _RS_BARE_FN.finditer(text):
            name = m.group(2)
            if name in seen:
                continue
            body = extract_rs_body(text, text.find("{", m.end()))
            code = (m.group(0).strip() + "\n" + body).strip()
            if len(code) < MIN_CODE_CHARS:
                continue
            seen.add(name)
            chunks.append({
                "id":     make_id(repo, str(path), name),
                "source": "source",
                "repo":   repo,
                "file":   str(path.relative_to(BASE)),
                "lang":   "rust",
                "kind":   "raw_code",
                "title":  name,
                "body":   "",
                "code":   [code[:1200]],
            })

    return chunks


# ──────────────────────────────────────────────
# C / H extraction
# ──────────────────────────────────────────────

_C_BLOCK_COMMENT = re.compile(
    r"/\*\*(.*?)\*/\s*((?:static\s+|inline\s+|__always_inline\s+)*\w[\w\s\*]+\w\s*\([^)]*\)\s*\{)",
    re.DOTALL,
)

_C_BARE_FN = re.compile(
    r"^(?:static\s+|inline\s+|__always_inline\s+)?(?:int|void|__u32|__u64|bool|struct\s+\w+\s*\*?)\s+"
    r"(\w+)\s*\([^)]{0,200}\)\s*\{",
    re.MULTILINE,
)


def extract_c_body(text: str, start: int) -> str:
    depth, i, limit = 0, start, min(start + 2000, len(text))
    while i < limit:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return text[start : start + 600]


def process_c(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    # Only include C files that are actual eBPF kernel programs or libbpf API usage
    if not BPF_C_SIGNALS.search(text):
        return []

    chunks = []
    seen = set()

    for m in _C_BLOCK_COMMENT.finditer(text):
        doc  = m.group(1).strip().replace("*", "").strip()
        decl = m.group(2).strip()
        name = re.search(r"\b(\w+)\s*\(", decl)
        name = name.group(1) if name else decl[:40]
        body = extract_c_body(text, m.end() - 1)
        code = (decl + "\n" + body).strip()

        if len(code) < MIN_CODE_CHARS or name in seen:
            continue
        seen.add(name)

        chunks.append({
            "id":     make_id(repo, str(path), name),
            "source": "source",
            "repo":   repo,
            "file":   str(path.relative_to(BASE)),
            "lang":   "c",
            "kind":   "doc_code",
            "title":  name,
            "body":   doc,
            "code":   [code],
        })

    for m in _C_BARE_FN.finditer(text):
        name = m.group(1)
        if name in seen:
            continue
        body = extract_c_body(text, text.find("{", m.end() - 1))
        code = (m.group(0).strip() + "\n" + body).strip()
        if len(code) < MIN_CODE_CHARS:
            continue
        seen.add(name)
        chunks.append({
            "id":     make_id(repo, str(path), name),
            "source": "source",
            "repo":   repo,
            "file":   str(path.relative_to(BASE)),
            "lang":   "c",
            "kind":   "raw_code",
            "title":  name,
            "body":   "",
            "code":   [code[:1200]],
        })

    return chunks


# ──────────────────────────────────────────────
# Go extraction
# ──────────────────────────────────────────────

_GO_DOC_FN = re.compile(
    r"((?://[^\n]*\n)+)"
    r"[ \t]*(func\s+(?:\([^)]*\)\s*)?\w+\s*\([^{]*)\{",
    re.DOTALL,
)

_GO_BARE_FN = re.compile(
    r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(",
    re.MULTILINE,
)


def extract_go_body(text: str, start: int) -> str:
    depth, i, limit = 0, start, min(start + 2000, len(text))
    while i < limit:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return text[start : start + 600]


def process_go(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    # Only include Go files that use the cilium/ebpf library
    if not BPF_GO_SIGNALS.search(text):
        return []

    chunks = []
    seen = set()

    for m in _GO_DOC_FN.finditer(text):
        doc  = "\n".join(l.lstrip("/").strip() for l in m.group(1).splitlines()).strip()
        decl = m.group(2).strip()
        name = re.search(r"\b(\w+)\s*\(", decl)
        name = name.group(1) if name else decl[:40]
        body = extract_go_body(text, m.end() - 1)
        code = (decl + " {\n" + body).strip()

        if len(code) < MIN_CODE_CHARS or name in seen:
            continue
        seen.add(name)

        chunks.append({
            "id":     make_id(repo, str(path), name),
            "source": "source",
            "repo":   repo,
            "file":   str(path.relative_to(BASE)),
            "lang":   "go",
            "kind":   "doc_code",
            "title":  name,
            "body":   doc,
            "code":   [code],
        })

    return chunks


# ──────────────────────────────────────────────
# Python extraction (BCC scripts)
# ──────────────────────────────────────────────

_PY_BPF_PROG = re.compile(
    r'(BPF_[A-Z_]+|b\s*=\s*BPF)\s*\(',   # BPF() call
)

_PY_FUNC = re.compile(
    r'^(def\s+\w+\([^)]*\):)',
    re.MULTILINE,
)


def process_python(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    # Only include Python files that look like BCC programs
    if not _PY_BPF_PROG.search(text):
        return []

    return [{
        "id":     make_id(repo, str(path)),
        "source": "source",
        "repo":   repo,
        "file":   str(path.relative_to(BASE)),
        "lang":   "python",
        "kind":   "raw_code",
        "title":  path.stem,
        "body":   "",
        "code":   [text[:3000]],
    }]


# ──────────────────────────────────────────────
# RST extraction (kernel docs)
# ──────────────────────────────────────────────

_RST_HEADING = re.compile(
    r"^(.+)\n[=\-~^\"#*+]{3,}\s*$",
    re.MULTILINE,
)

_RST_CODE_BLOCK = re.compile(
    r"\.\.\s+code-block::\s*(\w*)\n\n((?:[ \t]+[^\n]*\n|\n)+)",
)

_RST_LITERAL_BLOCK = re.compile(
    r"::\s*\n\n((?:[ \t]+[^\n]*\n|\n)+)",
)


def process_rst(repo: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []

    if not MD_SIGNAL_WORDS.search(text):
        return []

    # Extract code blocks
    code_blocks = []
    for m in _RST_CODE_BLOCK.finditer(text):
        lang = m.group(1).strip() or "c"
        code = re.sub(r"^[ \t]{3,}", "", m.group(2), flags=re.MULTILINE).strip()
        if len(code) >= MIN_CODE_CHARS:
            code_blocks.append(code)
    for m in _RST_LITERAL_BLOCK.finditer(text):
        code = re.sub(r"^[ \t]{3,}", "", m.group(1), flags=re.MULTILINE).strip()
        if len(code) >= MIN_CODE_CHARS:
            code_blocks.append(code)

    chunks = []
    headings = list(_RST_HEADING.finditer(text))

    if not headings:
        body = _RST_CODE_BLOCK.sub("", _RST_LITERAL_BLOCK.sub("", text)).strip()
        if len(body) >= MIN_BODY_CHARS:
            for i, part in enumerate(split_markdown(body)):
                chunks.append({
                    "id":     make_id(repo, str(path), f"full_{i}"),
                    "source": "kernel_docs",
                    "repo":   repo,
                    "file":   str(path.relative_to(BASE)),
                    "lang":   "text",
                    "kind":   "tutorial_section",
                    "title":  path.stem.replace("_", " ").replace("-", " ").title(),
                    "body":   part,
                    "code":   code_blocks[:3],
                })
        return chunks

    for idx, m in enumerate(headings):
        start = m.end()
        end   = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
        section_raw  = text[start:end].strip()
        section_code = []
        for cb in _RST_CODE_BLOCK.finditer(section_raw):
            code = re.sub(r"^[ \t]{3,}", "", cb.group(2), flags=re.MULTILINE).strip()
            if len(code) >= MIN_CODE_CHARS:
                section_code.append(code)
        body = _RST_CODE_BLOCK.sub("", _RST_LITERAL_BLOCK.sub("", section_raw)).strip()

        if len(body) < MIN_BODY_CHARS and not section_code:
            continue

        title = m.group(1).strip()
        for i, part in enumerate(split_markdown(body)):
            chunks.append({
                "id":     make_id(repo, str(path), f"{title}_{i}"),
                "source": "kernel_docs",
                "repo":   repo,
                "file":   str(path.relative_to(BASE)),
                "lang":   "text",
                "kind":   "tutorial_section",
                "title":  title,
                "body":   part,
                "code":   section_code[:4],
            })

    return chunks


# ──────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────

PROCESSORS = {
    "rs":  process_rust,
    "c":   process_c,
    "h":   process_c,
    "go":  process_go,
    "py":  process_python,
    "rst": process_rst,
}


def process_file(args: tuple) -> list[dict]:
    repo, path_str, langs, include_md = args
    path = Path(path_str)

    if should_skip(path):
        return []

    suffix = path.suffix.lstrip(".")

    if suffix == "md" and include_md:
        return process_markdown(repo, path)

    if suffix == "rst":
        return process_rst(repo, path)

    if suffix in langs and suffix in PROCESSORS:
        return PROCESSORS[suffix](repo, path)

    return []


def collect_files(repo: str, langs: list, include_md: bool) -> list[tuple]:
    root = BASE / repo
    if not root.exists():
        return []

    exts = set(langs)
    if include_md:
        exts.add("md")

    # Always include RST for repos that have kernel/reference docs
    if repo in ("linux-bpf-docs", "bpf-docs"):
        exts.add("rst")

    tasks = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lstrip(".") in exts:
            if not should_skip(path):
                tasks.append((repo, str(path), langs, include_md))
    return tasks


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)

    all_tasks = []
    for repo, (langs, include_md) in REPOS.items():
        tasks = collect_files(repo, langs, include_md)
        print(f"  {repo:<30} {len(tasks):>5} files")
        all_tasks.extend(tasks)

    print(f"\nTotal files to process: {len(all_tasks)}")
    print(f"Workers: {WORKERS}\n")

    total_chunks = 0
    seen_ids = set()

    with open(OUT, "w") as f, mp.Pool(WORKERS) as pool:
        for chunks in tqdm(
            pool.imap_unordered(process_file, all_tasks, chunksize=8),
            total=len(all_tasks),
            desc="Extracting",
        ):
            for chunk in chunks:
                if chunk["id"] in seen_ids:
                    continue
                seen_ids.add(chunk["id"])
                f.write(json.dumps(chunk) + "\n")
                total_chunks += 1

    print(f"\nDone. {total_chunks:,} chunks → {OUT}")

    # Summary by repo + kind
    from collections import Counter
    counts: Counter = Counter()
    with open(OUT) as f:
        for line in f:
            obj = json.loads(line)
            counts[(obj["repo"], obj["kind"])] += 1

    print("\nChunks per repo:")
    repo_totals: Counter = Counter()
    for (repo, kind), n in sorted(counts.items()):
        repo_totals[repo] += n
    for repo, n in sorted(repo_totals.items(), key=lambda x: -x[1]):
        print(f"  {repo:<30} {n:>6}")


if __name__ == "__main__":
    main()
