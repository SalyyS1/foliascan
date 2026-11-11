#!/usr/bin/env python3
"""Extract the authoritative list of Folia-hostile API sites from the Folia patch set.

Reads PaperMC/Folia's *.patch files and reports every ADDED line that makes an API
call fail under regionised threading, attributed to the file and (where git recorded
it) the enclosing method from the hunk header. This is the provenance source for the
scanner's rule table - rules are derived from Folia's own source, not from guesswork.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Added lines that signal "this API path is not usable / not safe under region threading".
SIGNALS = (
    ("unsupported", re.compile(r"throw new UnsupportedOperationException\((.*)\)")),
    ("thread_check", re.compile(r"TickThread\.ensureTickThread\((.*)\)")),
    ("global_thread_check", re.compile(r"RegionizedServer\.ensureGlobalTickThread\((.*)\)")),
    ("deprecated", re.compile(r"^\s*@Deprecated\b")),
)

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$")
NEWFILE = re.compile(r"^\+\+\+ b/(.+)$")

# A Java member declaration: modifiers, return type, name, open paren. Deliberately
# loose - it only has to beat "nearest class declaration" for attribution quality.
MEMBER = re.compile(
    r"^\s*(?:@\w+\s+)*"
    r"(?:public|protected|private)\s+"
    r"(?:static\s+|final\s+|synchronized\s+|abstract\s+|native\s+|default\s+)*"
    r"(?:<[^>]+>\s+)?"
    r"[\w.$<>\[\],?\s]+?\s+"
    r"(\w+)\s*\("
)
NOT_MEMBER = re.compile(r"\b(?:class|interface|enum|record|new)\b")


def member_name(line: str) -> str | None:
    """Return the method/ctor name declared on this line, if it declares one."""
    if NOT_MEMBER.search(line):
        return None
    m = MEMBER.match(line)
    return m.group(1) if m else None


@dataclass
class Finding:
    kind: str
    patch: str
    file: str
    java_class: str
    enclosing: str
    detail: str
    line: int


def scan(patch_path: Path, repo_root: Path) -> list[Finding]:
    out: list[Finding] = []
    cur_file = "?"
    cur_hunk = ""
    cur_member = ""
    text = patch_path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        m = NEWFILE.match(raw)
        if m:
            cur_file = m.group(1)
            cur_hunk = cur_member = ""
            continue
        m = HUNK.match(raw)
        if m:
            cur_hunk = m.group(1).strip()
            # The hunk header often names the enclosing member already.
            cur_member = member_name(cur_hunk) or ""
            continue
        if not raw or raw[0] not in "+- ":
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue

        body = raw[1:]
        # Track the closest member declaration seen so far, from any diff side.
        found_member = member_name(body)
        if found_member:
            cur_member = found_member

        if not raw.startswith("+"):
            continue
        for kind, pat in SIGNALS:
            m = pat.search(body)
            if not m:
                continue
            detail = (m.group(1).strip() if m.groups() else body.strip())
            out.append(
                Finding(
                    kind=kind,
                    patch=str(patch_path.relative_to(repo_root)).replace("\\", "/"),
                    file=cur_file,
                    java_class=Path(cur_file).stem,
                    enclosing=cur_member or cur_hunk,
                    detail=detail[:160],
                    line=lineno,
                )
            )
            break
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: extract_folia_throws.py <path-to-folia-checkout> [output.json]",
            file=sys.stderr,
        )
        return 2
    repo_root = Path(sys.argv[1]).resolve()
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("folia-throw-sites.json")
    patches = sorted(repo_root.rglob("*.patch"))
    if not patches:
        print(f"no .patch files under {repo_root}", file=sys.stderr)
        return 1

    findings: list[Finding] = []
    for p in patches:
        findings.extend(scan(p, repo_root))

    # API-facing surface is what plugin authors can actually call.
    api_facing = [
        f
        for f in findings
        if ("/org/bukkit/craftbukkit/" in f.file or "/org/bukkit/" in f.file)
        and f.kind != "thread_check"
    ]

    print(f"patches scanned      : {len(patches)}")
    print(f"total signal sites   : {len(findings)}")
    print(f"  unsupported        : {sum(1 for f in findings if f.kind == 'unsupported')}")
    print(f"  thread_check       : {sum(1 for f in findings if f.kind == 'thread_check')}")
    print(f"  global_thread_check: {sum(1 for f in findings if f.kind == 'global_thread_check')}")
    print(f"  deprecated         : {sum(1 for f in findings if f.kind == 'deprecated')}")
    print(f"api-facing (bukkit)  : {len(api_facing)}")
    print()
    print("=== API-facing failure sites (class :: enclosing :: message) ===")
    seen = set()
    for f in sorted(api_facing, key=lambda x: (x.java_class, x.enclosing)):
        key = (f.java_class, f.enclosing, f.detail)
        if key in seen:
            continue
        seen.add(key)
        print(f"{f.java_class:28} :: {f.enclosing[:64]:64} :: {f.detail[:56]}")

    out_path.write_text(
        json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8"
    )
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
