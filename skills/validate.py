#!/usr/bin/env python3
"""Check the skills in this folder.

    python3 skills/validate.py            static checks
    python3 skills/validate.py --run      also run every helper script and module a skill names with --help

For each skills/<name>/SKILL.md:
  * YAML front matter with `name` and `description` and nothing else;
  * `name` equals the folder name: lower-case letters, digits and hyphens, at most 64 characters;
  * `description` is 40 to 1024 characters and says when to use the skill ("Use when ...");
  * the body has the sections "## Never without a human" and "## Commands";
  * every `sf-smartdelegate ...` command quoted in the skill (fenced blocks and inline code) names a
    command of the CLI's help text, and every --option it uses appears in that help text
    (sf_smartdelegate.cli.HELP and sf_smartdelegate.bridges.cli);
  * every `python3 <path>` names a file in this repository; every `python3 -m <module>` is one of the
    repository's entry points;
  * no network call in the skill text: no curl or wget, no URL other than loopback.

Exit status 0 when every skill is clean, 1 otherwise. Standard library plus the smartdelegate package.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
MODULES = {"sf_smartdelegate": None, "interfaces.contract": ROOT / "interfaces" / "contract" / "__main__.py"}
SECTIONS = ("## Never without a human", "## Commands")


def cli_surface() -> tuple:
    """(commands, options) the help texts name. A command is ("policy", "check") or ("info",)."""
    from sf_smartdelegate import cli
    from sf_smartdelegate.bridges import cli as bridge_cli
    commands, options = {("--demo",), ("--version",), ("--help",)}, {"--help"}
    for line in cli.HELP.splitlines():
        m = re.match(r"  ([a-z][a-z-]*)((?: [a-z][a-z|-]*)?)(?=\s|$)", line)
        if m:
            first, second = m.group(1), m.group(2).strip()
            if first in ("smartdelegate", "sf-smartdelegate", "token") and not second:
                continue
            for s in (second.split("|") if second else [""]):
                commands.add((first, s) if s else (first,))
        for alt in re.findall(r"sync-[a-z-]+(?:\|sync-[a-z-]+)+", line):
            commands.update(("bridge", s) for s in alt.split("|"))
    text = cli.HELP + (bridge_cli.__doc__ or "")
    for line in (bridge_cli.__doc__ or "").splitlines():
        m = re.match(r"    ([a-z][a-z-]+)\s", line)
        if m and (m.group(1).startswith("sync-") or m.group(1) in ("map-claims", "aws-session-policy", "gcp-boundary", "azure-scopes", "ceiling")):
            commands.add(("bridge", m.group(1)))
    options.update(re.findall(r"(?<![\w-])(--[a-z][a-z-]*|-n)\b", text))
    return commands, options


def front_matter(text: str) -> tuple:
    """(fields, body) or raises ValueError. The subset of YAML a skill needs: `key: value` lines."""
    if not text.startswith("---\n"):
        raise ValueError("no front matter: the file must start with ---")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("the front matter is not closed with ---")
    fields = {}
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or not key.strip() or key != key.strip():
            raise ValueError(f"front matter line is not `key: value`: {line!r}")
        fields[key] = value.strip().strip('"')
    return fields, text[end + 5:]


def quoted_commands(body: str) -> list:
    """Command lines in fenced blocks (with shell continuations joined) and in inline code."""
    out, fenced = [], re.findall(r"```[a-z]*\n(.*?)```", body, re.S)
    for block in fenced:
        for line in block.replace("\\\n", " ").splitlines():
            line = line.strip()
            line = line[2:] if line.startswith("$ ") else line
            if line and not line.startswith("#"):
                out.append(line)
    out += [c.strip() for c in re.findall(r"`([^`\n]+)`", re.sub(r"```.*?```", "", body, flags=re.S))]
    return out


def check_command(line: str, commands: set, options: set) -> list:
    problems = []
    for part in re.split(r"\s*(?:\|\||&&|\||;)\s*", line):
        part = re.sub(r"^(?:[A-Z_]+=\S+\s+)+", "", part.strip())          # VAR=value prefixes
        part = re.sub(r"^[A-Z_]+=\$\((.*)\)$", r"\1", part)                  # VAR=$(command)
        try:
            words = shlex.split(part, comments=True)
        except ValueError:
            continue
        if not words:
            continue
        head = words[0]
        if head in ("smartdelegate", "sf-smartdelegate") or head.endswith(("/smartdelegate", "/sf-smartdelegate")):
            args = [w for w in words[1:]]
            if not args or args[0] == "...":
                continue
            if (args[0],) not in commands and tuple(args[:2]) not in commands:
                problems.append(f"`{' '.join(words[:3])}`: not a command of `sf-smartdelegate --help`")
            for w in args:
                if w == "--":
                    break
                if re.fullmatch(r"--[a-z][a-z-]*", w) and w not in options:
                    problems.append(f"`{' '.join(words[:3])} ... {w}`: option {w} is not in the help text")
        elif head in ("python3", "python") and len(words) > 1:
            if words[1] == "-m":
                if len(words) < 3 or words[2] not in MODULES:
                    problems.append(f"`{part}`: python3 -m {words[2] if len(words) > 2 else ''} is not an entry point of this repository")
            elif not words[1].startswith("-") and not (ROOT / words[1]).is_file():
                problems.append(f"`{part}`: {words[1]} does not exist in the repository")
        elif head in ("curl", "wget", "nc", "ssh", "scp"):
            problems.append(f"`{part}`: a skill must not make network calls")
    return problems


def runnable(body: str) -> list:
    """argv lists to try with --help: the helper scripts and modules the skill names."""
    seen, out = set(), []
    for line in quoted_commands(body):
        for part in re.split(r"\s*(?:\|\||&&|\||;)\s*", line):
            try:
                words = shlex.split(re.sub(r"^(?:[A-Z_]+=\S+\s+)+", "", part.strip()), comments=True)
            except ValueError:
                continue
            if len(words) > 2 and words[0] == "python3" and words[1] == "-m" and words[2] in MODULES:
                key = ("-m", words[2])
            elif len(words) > 1 and words[0] == "python3" and (ROOT / words[1]).is_file():
                key = (words[1],)
            else:
                continue
            if key not in seen:
                seen.add(key)
                out.append([sys.executable, *key, "--help"])
    return out


def validate(skill_dir: Path, commands: set, options: set, run: bool = False) -> list:
    problems, name = [], skill_dir.name
    path = skill_dir / "SKILL.md"
    if not path.is_file():
        return [f"{name}: no SKILL.md"]
    try:
        fields, body = front_matter(path.read_text(encoding="utf-8"))
    except ValueError as e:
        return [f"{name}: {e}"]
    if set(fields) != {"name", "description"}:
        problems.append(f"{name}: front matter must have exactly `name` and `description`, found {sorted(fields)}")
    if fields.get("name") != name:
        problems.append(f"{name}: front matter name {fields.get('name')!r} is not the folder name")
    if not NAME.fullmatch(name) or len(name) > 64:
        problems.append(f"{name}: the name must be lower-case letters, digits and hyphens, at most 64 characters")
    d = fields.get("description", "")
    if not 40 <= len(d) <= 1024:
        problems.append(f"{name}: description has {len(d)} characters; 40 to 1024 are allowed")
    if "Use when" not in d:
        problems.append(f"{name}: the description must say when to use the skill (\"Use when ...\")")
    for section in SECTIONS:
        if section not in body:
            problems.append(f"{name}: section {section!r} is missing")
    for url in re.findall(r"https?://[^\s)`\"'>]+", body):
        if not re.match(r"https?://(127\.0\.0\.1|localhost)([:/]|$)", url):
            problems.append(f"{name}: URL {url} in the skill text (only loopback addresses are allowed)")
    for line in quoted_commands(body):
        problems += [f"{name}: {p}" for p in check_command(line, commands, options)]
    for script in sorted((skill_dir / "scripts").glob("*")) if (skill_dir / "scripts").is_dir() else []:
        if script.suffix == ".py" and f"skills/{name}/scripts/{script.name}" not in body:
            problems.append(f"{name}: scripts/{script.name} is not mentioned in SKILL.md")
    if run:
        import os
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT), os.environ.get("PYTHONPATH", "")])}
        for argv in runnable(body):
            r = subprocess.run(argv, capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=60)
            if r.returncode != 0 or not r.stdout.strip():
                problems.append(f"{name}: `{' '.join(argv[1:])}` exited {r.returncode} without help text")
    return problems


def main(argv: list) -> int:
    if set(argv) - {"--run"}:
        print(__doc__)
        return 0 if argv in (["--help"], ["-h"]) else 1
    commands, options = cli_surface()
    skills = sorted(p for p in HERE.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))
    problems = [p for s in skills for p in validate(s, commands, options, run="--run" in argv)]
    for p in problems:
        print(p)
    print(f"{len(skills)} skills, {len(problems)} problems")
    return 1 if problems or not skills else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
