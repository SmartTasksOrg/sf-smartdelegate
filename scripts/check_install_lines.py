#!/usr/bin/env python3
"""Fail when a file in this repository tells people to install a package by a
registry name that names.json does not mark as registered by the owners.

Why: on PyPI, npm, crates.io and the other public registries the first person
to publish a name owns it. An install line for a name the owners do not hold
installs whoever registers it first. See SECURITY.md.

Usage (from the repository root):
    python scripts/check_install_lines.py            # check, exit 1 on a problem
    python scripts/check_install_lines.py --list     # also print every install line found
    python scripts/check_install_lines.py --names path/to/names.json --root path/to/repo

Standard library only. Python 3.9 or later. Exit codes: 0 clean, 1 problems
found, 2 names.json missing or invalid.

A line that must mention an install command without meaning it (for example a
warning "do not run pip install smartsim") is skipped when it contains the
marker  check-install-lines: ignore  (in a comment where the format allows one).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

TEXT_EXT = {
    ".md", ".markdown", ".rst", ".txt", ".html", ".htm", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd",
    ".php", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".xml", ".gemspec", ".swift", ".ipynb", ".svelte", ".vue",
}
TEXT_NAMES = {"Makefile", "Dockerfile", "Gemfile", "Procfile", "Justfile"}
SKIP_PARTS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "__pycache__", "vendor"}
IGNORE_MARKER = "check-install-lines: ignore"

# (registry, compiled regex). Group "args" is what follows the command.
COMMANDS = [
    ("pypi", r"\b(?:python3?|py)(?:\s+-\d(?:\.\d+)?)?\s+-m\s+pip\s+install\b"),
    ("pypi", r"(?<![\w.-])pip3?\s+install\b"),
    ("pypi", r"\buv\s+pip\s+install\b"),
    ("pypi", r"\buv\s+(?:tool\s+install|add)\b"),
    ("pypi", r"\bpipx\s+(?:install|run)\b"),
    ("pypi-run", r"\buvx\b"),
    ("npm", r"\bnpm\s+(?:install|i|add)\b"),
    ("npm", r"\b(?:yarn|pnpm)\s+add\b"),
    ("npm-run", r"\b(?:npx|pnpx|bunx)\b"),
    ("npm-run", r"\b(?:pnpm|yarn)\s+dlx\b"),
    ("crates", r"\bcargo\s+(?:add|install)\b"),
    ("packagist", r"\bcomposer\s+(?:global\s+)?require\b"),
    ("go", r"\bgo\s+(?:get|install)\b"),
    ("rubygems", r"\bgem\s+install\b"),
    ("nuget", r"\bdotnet\s+add\s+(?:\S+\s+)?package\b"),
    ("docker", r"\bdocker\s+(?:pull|run)\b"),
]
COMMANDS = [(r, re.compile(p)) for r, p in COMMANDS]

# options whose next token is a value, not a package
VALUE_OPTS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links", "--target", "-t", "--prefix", "--root", "--python", "-p", "--from", "--with",
    "--version", "--vers", "--git", "--path", "--branch", "--tag", "--rev", "--registry", "--source",
    "--outDir", "--framework",
}
# for docker -p/-e/-v take a value; for pip -e takes a path (handled as local anyway)
DOCKER_VALUE_OPTS = {"-p", "--publish", "-v", "--volume", "-e", "--env", "--name", "--restart", "-w", "--workdir",
                     "--network", "--platform", "--entrypoint", "-u", "--user", "--mount", "--label", "-l",
                     "--env-file", "--cpus", "--memory", "-m", "--add-host", "--hostname", "-h"}
PKG_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._~/-]*$")
ACTION_INPUT_RE = re.compile(r"\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def norm(registry: str, name: str) -> str:
    if registry in ("pypi", "pypi-run"):
        return pep503(name)
    if registry in ("nuget", "npm", "npm-run", "crates", "packagist", "rubygems", "docker"):
        return name.lower()
    return name


def tracked_files(root: str) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
        files = [f for f in out.stdout.decode("utf-8", "replace").split("\0") if f]
        if files:
            return files
    except (OSError, subprocess.CalledProcessError):
        pass
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_PARTS]
        for n in names:
            files.append(os.path.relpath(os.path.join(base, n), root).replace(os.sep, "/"))
    return files


def is_text(path: str) -> bool:
    name = os.path.basename(path)
    return name in TEXT_NAMES or os.path.splitext(name)[1].lower() in TEXT_EXT


def cut_args(line: str, m: re.Match) -> str:
    args = line[m.end():]
    # If the command sits inside a quoted string ("install": "pip install x"),
    # the arguments end at the closing quote of that string.
    before = line[: m.start()].rstrip()
    if before and before[-1] in "\"'":
        q = before[-1]
        args = args.split(q, 1)[0]
    # End of the shell command or of the inline code span.
    out, quote = [], None
    for ch in args:
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch in "`|;&<>)#\\" or ch == "\n":
            break
        out.append(ch)
    return "".join(out)


def split_tokens(args: str) -> list[str]:
    try:
        return shlex.split(args, posix=True)
    except ValueError:
        return [t.strip("\"'") for t in args.split()]


def candidates(registry: str, args: str) -> list[str]:
    toks = split_tokens(args)
    value_opts = DOCKER_VALUE_OPTS if registry == "docker" else VALUE_OPTS
    first_only = registry in ("pypi-run", "npm-run", "docker")
    out, skip = [], False
    i = 0
    while i < len(toks):
        t = toks[i]
        i += 1
        if skip:
            skip = False
            continue
        if registry == "npm-run" and t in ("-p", "--package") and i < len(toks):
            return [toks[i]]  # npx -p <package> <command>: the package is what gets fetched
        if t in value_opts:
            # uvx --from <pkg> <cmd>: the package is the value of --from
            if registry == "pypi-run" and t == "--from" and i < len(toks):
                return [toks[i]]
            skip = True
            continue
        if t.startswith("-"):
            continue
        out.append(t)
        if first_only:
            break
    return out


def classify(registry: str, token: str):
    """Return (kind, name). kind: local | git | name | dynamic | skip."""
    t = token.strip().strip(",")
    if not t:
        return "skip", t
    if ACTION_INPUT_RE.search(t):
        return "dynamic", t
    if t.startswith(("$", "%", "{", "<")):
        return "skip", t
    if registry in ("pypi", "pypi-run") and " @ " in t:  # PEP 508 direct reference: "name @ git+https://..."
        return "git", t.split(" @ ", 1)[1].strip()
    if t.startswith(("git+", "https://", "http://", "git@")):
        return "git", t
    if t in (".", "..") or t.startswith(("./", "../", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", t):
        return "local", t
    if t.endswith((".whl", ".tar.gz", ".zip", ".tgz", ".crate", ".phar", ".nupkg", ".gem")):
        return "local", t
    if registry in ("pypi", "pypi-run"):
        base = re.split(r"[\[=<>!~;@ ]", t, 1)[0]
    elif registry in ("npm", "npm-run"):
        base = t if t.startswith("@") and t.count("@") == 1 else re.sub(r"(?<!^)@.*$", "", t)
    elif registry == "go":
        base = t.split("@", 1)[0]
    elif registry == "docker":
        base = re.sub(r":[^/:]+$", "", re.sub(r"@sha256:[0-9a-f]+$", "", t))
    elif registry == "crates":
        base = t.split("@", 1)[0]
    elif registry == "packagist":
        base = t.split(":", 1)[0]
    else:
        base = t
    if not PKG_RE.match(base):
        return "skip", base
    return "name", base


def git_pinned(url: str, allowed_owners: list[str]) -> tuple[bool, str]:
    m = re.match(r"^(?:git\+)?https://github\.com/([^/]+)/([^/@#]+?)(?:\.git)?(?:@([^#\s]+))?(?:#.*)?$", url)
    if not m:
        return False, "git URL is not a github.com https URL"
    owner, _repo, ref = m.groups()
    if owner.lower() not in [o.lower() for o in allowed_owners]:
        return False, f"git URL points at {owner}, not at {', '.join(allowed_owners)}"
    if not ref:
        return False, "git URL is not pinned to a tag or commit (add @vX.Y.Z)"
    if ref in ("main", "master", "HEAD", "develop"):
        return False, f"git URL is pinned to the branch '{ref}', which moves; use a tag or commit"
    return True, ""


def action_input_default(text: str, name: str):
    m = re.search(r"(?m)^(\s*)" + re.escape(name) + r":\s*$", text)
    if not m:
        return None
    indent = len(m.group(1))
    for line in text[m.end():].splitlines()[1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        d = re.match(r"\s*default:\s*(.*)$", line)
        if d:
            return d.group(1).strip().strip("\"'")
    return None


def load_names(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema") != 1 or not isinstance(data.get("names"), list):
        raise ValueError("names.json must have \"schema\": 1 and a \"names\" list")
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--names", default=None, help="default: <root>/names.json")
    ap.add_argument("--list", action="store_true", help="print every install line found, not only problems")
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root)
    names_path = a.names or os.path.join(root, "names.json")
    try:
        cfg = load_names(names_path)
    except (OSError, ValueError) as e:
        print(f"names.json: {e}", file=sys.stderr)
        return 2

    registered, known_unregistered = {}, {}
    for e in cfg["names"]:
        reg = e["registry"]
        key = (reg, norm(reg, e["name"]))
        (registered if e.get("registered") is True else known_unregistered)[key] = e
    third = {(reg, norm(reg, n)) for reg, lst in cfg.get("third_party", {}).items() for n in lst}
    # images built locally by a command in the same docs (docker build -t <name>); an unqualified
    # name is Docker Hub's official-images namespace, which nobody outside Docker can publish to
    third |= {("docker", n.lower()) for n in cfg.get("local_images", [])}
    owners = cfg.get("git_owners", ["SmartTasksOrg"])
    excludes = cfg.get("exclude_paths", [])

    def lookup(reg: str, name: str):
        regs = {"pypi-run": ["pypi"], "npm-run": ["npm"], "docker": ["docker", "ghcr"]}.get(reg, [reg])
        for r in regs:
            k = (r, norm(r, name))
            if k in registered:
                return "ok", ""
            if k in known_unregistered:
                return "error", f"names.json marks {r}:{name} as NOT registered by the owners"
            if k in third:
                return "ok", "third party"
        if reg in ("pypi-run", "npm-run"):
            return "error", f"runs the {regs[0]} package '{name}' by name; it is not in names.json"
        return "error", f"'{name}' is not in names.json (registered by the owners, or listed under third_party)"

    self_path = os.path.realpath(__file__)
    problems, seen = [], []
    for rel in tracked_files(root):
        if not is_text(rel) or any(fnmatch.fnmatch(rel, g) for g in excludes):
            continue
        if any(p in SKIP_PARTS for p in rel.split("/")[:-1]):
            continue
        path = os.path.join(root, rel)
        if os.path.realpath(path) == self_path or rel.endswith("scripts/check_install_lines.py"):
            continue  # this script's own documentation mentions install commands
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        is_action = os.path.basename(rel) in ("action.yml", "action.yaml")
        for lineno, line in enumerate(text.splitlines(), 1):
            if IGNORE_MARKER in line:
                continue
            for reg, rx in COMMANDS:
                for m in rx.finditer(line):
                    args = cut_args(line, m)
                    for tok in candidates(reg, args):
                        kind, name = classify(reg, tok)
                        if kind in ("skip", "local"):
                            continue
                        if kind == "dynamic":
                            inp = ACTION_INPUT_RE.search(name).group(1)
                            default = action_input_default(text, inp) if is_action else None
                            if default is None:
                                continue
                            if default == "":
                                continue  # empty default: the action must install from its own path
                            kind, name = classify(reg, default)
                            if kind in ("skip", "local"):
                                continue
                            where = f"default of input '{inp}'"
                        else:
                            where = ""
                        if kind == "git":
                            ok, why = git_pinned(name, owners)
                            status, reason = ("ok", "") if ok else ("error", why)
                        else:
                            status, reason = lookup(reg, name)
                        rec = (rel, lineno, reg.replace("-run", ""), name, status, (where + " " + reason).strip())
                        if any(r[:4] == rec[:4] for r in seen):
                            continue
                        seen.append(rec)
                        if status == "error":
                            problems.append(rec)

    # server.json: every package the MCP registry entry points at must be ours and registered
    for rel in tracked_files(root):
        if os.path.basename(rel) != "server.json":
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                sj = json.load(f)
        except (OSError, ValueError):
            continue
        pk = sj.get("packages")
        if isinstance(pk, dict):
            problems.append((rel, 0, "mcp", "packages", "error", "'packages' must be a list (MCP server.json schema)"))
            continue
        for p in pk or []:
            reg = {"pypi": "pypi", "npm": "npm", "cargo": "crates", "nuget": "nuget", "oci": "docker"}.get(p.get("registryType"), p.get("registryType"))
            ident = str(p.get("identifier", ""))
            if reg == "mcpb":
                continue
            status, reason = lookup(reg, re.sub(r"[:@][^/]*$", "", ident) if reg == "docker" else ident)
            rec = (rel, 0, reg, ident, status, "server.json packages[].identifier " + reason)
            seen.append(rec)
            if status == "error":
                problems.append(rec)

    if a.list:
        for rel, ln, reg, name, status, reason in seen:
            print(f"{status:5} {rel}:{ln}: [{reg}] {name} {reason}".rstrip())
    for rel, ln, reg, name, status, reason in problems:
        print(f"{rel}:{ln}: [{reg}] {name}: {reason}", file=sys.stderr)
    if problems:
        print(f"\n{len(problems)} install line(s) name a package the owners do not hold. "
              "Replace them with the clone or pinned git install (see README 'Install'), "
              "or mark the name registered in names.json after it is published.", file=sys.stderr)
        return 1
    print(f"check_install_lines: {len(seen)} install reference(s) checked, all allowed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
