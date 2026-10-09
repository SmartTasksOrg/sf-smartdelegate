#!/usr/bin/env python3
"""SmartDelegate doctor: which toolchains are here, and what they enable.

    python3 scripts/doctor.py                 the table for this machine
    python3 scripts/doctor.py --json          the same, for machines
    python3 scripts/doctor.py --markdown      the table as Markdown (docs/BUILD.md)
    python3 scripts/doctor.py --platform windows|macos|apt|dnf
                                              show the install commands of another platform
    python3 scripts/doctor.py --require java,go
                                              exit 1 when one of these is not usable
    python3 scripts/doctor.py --install [--only java,go] [--dry-run]
                                              install what is missing with the platform's
                                              package manager; every command is printed
                                              before it runs; nothing is installed without
                                              this flag

Python 3.8+ and the standard library only, so that it runs before anything is
installed. Exit status: 0 when the reference requirement is met (a Python
3.10+ with the venv module; `cryptography` is installed into .venv by the
bootstrap), 1 when it is not, 2 for a usage error.

The minimum versions are the ones the port READMEs state (ports/README.md).
Nothing here reads or writes keys, tokens or state.
"""
from __future__ import print_function

import argparse
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IS_WINDOWS = os.name == "nt"
PROBE_TIMEOUT = 20   # seconds per probe


# --------------------------------------------------------------------------- probes

def which(name):
    return shutil.which(name)


def out_of(cmd, timeout=PROBE_TIMEOUT, env=None):
    """-> (exit status or None, combined output). Never raises."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    text = p.stdout.decode("utf-8", "replace")
    # the JVM prints this banner first when JAVA_TOOL_OPTIONS is set
    text = "\n".join(line for line in text.splitlines() if not line.startswith("Picked up "))
    return p.returncode, text


def vtuple(text):
    """'21.0.10+7' -> (21, 0, 10); None when there is no number."""
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


def vstr(t):
    return ".".join(str(x) for x in t) if t else ""


def at_least(found, wanted):
    if not found:
        return False
    n = max(len(found), len(wanted))
    pad = lambda t: tuple(t) + (0,) * (n - len(t))
    return pad(found) >= pad(wanted)


def probe_version(names, args, pattern=None):
    """First of `names` on PATH that answers. -> (path, version tuple, raw line)"""
    for name in names:
        path = which(name)
        if not path:
            continue
        status, text = out_of([path] + args)
        if status is None:
            continue
        line = next((l.strip() for l in text.splitlines() if l.strip()), "")
        if pattern:
            m = re.search(pattern, text)
            v = vtuple(m.group(1)) if m else None
        else:
            v = vtuple(line)
        if v and status == 0:
            return path, v, line
    return None, None, ""


PY_PROBE = ("import sys, json\n"
            "d = {'version': list(sys.version_info[:3]), 'executable': sys.executable}\n"
            "try:\n"
            "    import venv, ensurepip\n"
            "    d['venv'] = True\n"
            "except Exception:\n"
            "    d['venv'] = False\n"
            "try:\n"
            "    import cryptography\n"
            "    d['cryptography'] = cryptography.__version__\n"
            "except Exception:\n"
            "    d['cryptography'] = None\n"
            "print(json.dumps(d))\n")


def probe_python(cmd):
    status, text = out_of(list(cmd) + ["-c", PY_PROBE])
    if status != 0:
        return None
    try:
        d = json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    d["cmd"] = list(cmd)
    d["version"] = tuple(d["version"])
    return d


def venv_python(root=ROOT):
    """The interpreter of <root>/.venv (or of $SD_VENV), whether or not it exists."""
    venv = os.environ.get("SD_VENV") or os.path.join(root, ".venv")
    return os.path.join(venv, "Scripts", "python.exe") if IS_WINDOWS else os.path.join(venv, "bin", "python")


def python_candidates():
    seen = []
    for cmd in ([sys.executable], ["python3"], ["python"], ["python3.13"], ["python3.12"], ["python3.11"], ["python3.10"]):
        if cmd not in seen:
            seen.append(cmd)
    if IS_WINDOWS:
        seen.append(["py", "-3"])
    return seen


def find_base_python(minimum=(3, 10)):
    """The interpreter the virtualenv is made with: the first of the
    candidates (the one running this script, then python3, python, then the
    versioned names) that is at least `minimum` and has the venv module; when
    none has venv, the first that is new enough; else the newest there is.
    -> probe dict or None"""
    found = []
    for cmd in python_candidates():
        if cmd[0] != sys.executable and not which(cmd[0]):
            continue
        d = probe_python(cmd)
        if d and not any(os.path.normcase(d["executable"]) == os.path.normcase(x["executable"]) for x in found):
            found.append(d)
    if not found:
        return None
    ok = [d for d in found if d["version"] >= minimum]
    with_venv = [d for d in ok if d["venv"]]
    if with_venv:
        return with_venv[0]
    if ok:
        return ok[0]
    return sorted(found, key=lambda d: d["version"])[-1]


def pg_bin_dirs():
    dirs = []
    if os.environ.get("SD_PG_BIN"):
        dirs.append(os.environ["SD_PG_BIN"])
    dirs += sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True)
    dirs += sorted(glob.glob("/usr/pgsql-*/bin"), reverse=True)
    dirs += sorted(glob.glob("/opt/homebrew/opt/postgresql@*/bin") + glob.glob("/usr/local/opt/postgresql@*/bin"), reverse=True)
    if IS_WINDOWS:
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432")):
            if base:
                dirs += sorted(glob.glob(os.path.join(base, "PostgreSQL", "*", "bin")), reverse=True)
    return dirs


def find_pg(tool):
    path = which(tool)
    if path:
        return path
    exe = tool + (".exe" if IS_WINDOWS else "")
    for d in pg_bin_dirs():
        p = os.path.join(d, exe)
        if os.path.isfile(p):
            return p
    return None


# --------------------------------------------------------------------------- platform

def package_manager(forced=None):
    """-> one of windows, macos, apt, dnf, other"""
    if forced:
        return forced
    if IS_WINDOWS:
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    ids = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith(("ID=", "ID_LIKE=")):
                    ids += " " + line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass
    words = ids.split()
    if any(w in words for w in ("debian", "ubuntu")) or which("apt-get"):
        return "apt"
    if any(w in words for w in ("fedora", "rhel", "centos")) or which("dnf"):
        return "dnf"
    return "other"


WINGET = "winget install -e --id %s --accept-source-agreements --accept-package-agreements"

# Install commands per platform. `verified` says where the package name or id
# was checked when this file was written (2026-10):
#   windows  the id exists in github.com/microsoft/winget-pkgs (manifests tree)
#   macos    the formula or cask exists in Homebrew/homebrew-core or homebrew-cask
#   apt      `apt-cache policy` on Ubuntu 24.04
#   dnf      NOT verified (no Fedora machine or package index was reachable)
# A list holds several commands, run in order.
INSTALL = {
    "python": {
        "windows": [WINGET % "Python.Python.3.12"],
        "macos": ["brew install python@3.12"],
        "apt": ["apt-get install -y python3 python3-venv python3-pip"],
        "dnf": ["dnf install -y python3 python3-pip"],
    },
    "venv": {
        "windows": [],     # part of the python.org installer
        "macos": [],       # part of the Homebrew formula
        "apt": ["apt-get install -y python3-venv"],
        "dnf": [],         # part of python3 on Fedora
    },
    "java": {
        "windows": [WINGET % "EclipseAdoptium.Temurin.21.JDK"],
        "macos": ["brew install openjdk@21"],
        "apt": ["apt-get install -y openjdk-21-jdk-headless"],
        "dnf": ["dnf install -y java-21-openjdk-devel"],
    },
    "node": {
        "windows": [WINGET % "OpenJS.NodeJS.LTS"],
        "macos": ["brew install node"],
        "apt": ["apt-get install -y nodejs npm"],
        "dnf": ["dnf install -y nodejs npm"],
    },
    "go": {
        "windows": [WINGET % "GoLang.Go"],
        "macos": ["brew install go"],
        "apt": ["apt-get install -y golang-go"],
        "dnf": ["dnf install -y golang"],
    },
    "php": {
        "windows": [WINGET % "PHP.PHP.8.4"],
        "macos": ["brew install php"],
        "apt": ["apt-get install -y php-cli php-mbstring"],
        "dnf": ["dnf install -y php-cli php-mbstring php-sodium"],
    },
    "rust": {
        "windows": [WINGET % "Rustlang.Rustup", "rustup default stable"],
        "macos": ["brew install rustup", "rustup default stable"],
        "apt": ["apt-get install -y rustup", "rustup default stable"],
        "dnf": ["dnf install -y rustup", "rustup-init -y"],
    },
    "cc": {
        "windows": [WINGET % "Microsoft.VisualStudio.2022.BuildTools"
                    + ' --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'],
        "macos": ["xcode-select --install"],
        "apt": ["apt-get install -y build-essential"],
        "dnf": ["dnf install -y gcc"],
    },
    "docker": {
        "windows": [WINGET % "Docker.DockerDesktop"],
        "macos": ["brew install --cask docker-desktop"],
        "apt": ["apt-get install -y docker.io docker-compose-v2"],
        "dnf": ["dnf install -y moby-engine docker-compose"],
    },
    "postgres": {
        "windows": [WINGET % "PostgreSQL.PostgreSQL.16"],
        "macos": ["brew install postgresql@16"],
        "apt": ["apt-get install -y postgresql"],
        "dnf": ["dnf install -y postgresql-server"],
    },
    "powershell": {
        "windows": [WINGET % "Microsoft.PowerShell"],
        "macos": ["brew install powershell"],
        "apt": [],     # not in the Ubuntu archive; see the note
        "dnf": [],
    },
    "bash": {
        "windows": [WINGET % "Git.Git"],
        "macos": [], "apt": [], "dnf": [],
    },
}
# What could not be checked against an official source when this was written.
UNVERIFIED = {
    ("cc", "windows"): "the winget id is verified; the --override workload arguments are from Microsoft's Build Tools documentation and were not run",
}
NOTES = {
    ("php", "windows"): "then enable the extensions: copy php.ini-development to php.ini next to php.exe and uncomment extension=sodium, extension=openssl, extension=mbstring",
    ("php", "apt"): "sodium, openssl and json are part of php-cli (php8.x-common) on Debian and Ubuntu",
    ("rust", "apt"): "Debian/Ubuntu's own cargo package is too old (1.75 on Ubuntu 24.04); where there is no rustup package, use https://rustup.rs",
    ("rust", "windows"): "Rust on Windows links with MSVC: install the C compiler row as well",
    ("powershell", "apt"): "see https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux (Microsoft's package repository, or `snap install powershell --classic`)",
    ("powershell", "dnf"): "see https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux",
    ("java", "macos"): "Homebrew's openjdk is keg-only: add $(brew --prefix openjdk@21)/bin to PATH (brew prints the line)",
    ("postgres", "macos"): "keg-only: add $(brew --prefix postgresql@16)/bin to PATH",
    ("postgres", "windows"): "add C:\\Program Files\\PostgreSQL\\16\\bin to PATH, or set SD_PG_BIN",
    ("docker", "apt"): "then add your user to the docker group or run docker with sudo",
    ("bash", "windows"): "Git for Windows brings Git Bash; only needed to run the .sh scripts natively",
    ("node", "apt"): "Ubuntu 24.04 has Node 18; https://nodejs.org/en/download for a newer one",
}


def install_commands(key, pm):
    cmds = list(INSTALL.get(key, {}).get(pm, []))
    verified = pm != "dnf"
    if pm in ("other",):
        return [], False, "no package manager recognised: install it by hand"
    note = NOTES.get((key, pm), "")
    extra = UNVERIFIED.get((key, pm))
    if extra:
        note = (note + "; " if note else "") + extra
    return cmds, verified, note


def needs_root(cmd):
    return cmd.startswith(("apt-get ", "dnf "))


def as_run(cmd):
    """The command as it would be run here: with sudo in front when it needs
    root and we are not root."""
    if needs_root(cmd) and hasattr(os, "geteuid") and os.geteuid() != 0:
        return "sudo " + cmd
    return cmd


# --------------------------------------------------------------------------- the checks

OK, OLD, MISSING, PARTIAL = "ok", "too old", "missing", "partial"


def row(key, tool, found, required, status, enables, install_key=None, detail="", optional=True, path=None):
    return {"key": key, "tool": tool, "found": found, "required": required, "status": status, "enables": enables,
            "install_key": install_key or key, "detail": detail, "optional": optional, "path": path or ""}


def check_all(root=ROOT):
    rows = []

    # ---- Python (the reference): required
    base = find_base_python()
    vpy = venv_python(root)
    venv = probe_python([vpy]) if os.path.isfile(vpy) else None
    if base is None:
        rows.append(row("python", "python", "", ">= 3.10", MISSING, "the reference engine, CLI, daemon, proxies, harness, every test runner", optional=False))
    else:
        st = OK if base["version"] >= (3, 10) else OLD
        rows.append(row("python", "python", vstr(base["version"]), ">= 3.10", st,
                        "the reference engine, CLI, daemon, proxies, harness, every test runner", optional=False,
                        path=base["executable"]))
    if base is not None:
        rows.append(row("venv", "python venv module", "yes" if base["venv"] else "", "present", OK if base["venv"] else MISSING,
                        "the .venv the bootstrap creates", optional=False, path=base["executable"]))
    where = venv or base
    crypt = where.get("cryptography") if where else None
    cst = OK if at_least(vtuple(crypt), (41,)) else (OLD if crypt else MISSING)
    rows.append(row("cryptography", "python: cryptography", crypt or "", ">= 41", cst,
                    "Ed25519 and ID-token signatures in the reference", install_key="-",
                    detail=("in .venv" if venv else "in " + (base["executable"] if base else "?"))
                    + ("" if cst == OK else "; the bootstrap installs it into .venv (pip install -e .)")))

    # ---- Java
    jpath, jv, _ = probe_version(["java"], ["-version"], r'version "?([0-9][0-9._]*)')
    cpath, cv, _ = probe_version(["javac"], ["-version"], r"javac ([0-9][0-9._]*)")
    for t in ("jv", "cv"):
        v = locals()[t]
        if v and v[0] == 1 and len(v) > 1:      # "1.8.0" is Java 8
            if t == "jv":
                jv = (v[1],)
            else:
                cv = (v[1],)
    JAVA_ENABLES = "ports/java (engine, CLI, daemon); a Java 17+ runtime also runs Keycloak for live/idp"
    if jv and cv:
        low = min(jv, cv)
        st = OK if at_least(low, (17,)) else OLD
        det = ""
        if st == OK and not which("jar"):
            st, det = PARTIAL, "the `jar` tool is not on PATH (ports/java/build.sh needs it): install a full JDK"
        rows.append(row("java", "java + javac + jar (JDK)", vstr(low), ">= 17", st, JAVA_ENABLES, detail=det, path=cpath))
    elif jv and not cv:
        rows.append(row("java", "java + javac + jar (JDK)", vstr(jv) + " (JRE only)", ">= 17", PARTIAL, JAVA_ENABLES,
                        detail="java is here but javac is not: install a JDK, not a JRE", path=jpath))
    else:
        rows.append(row("java", "java + javac + jar (JDK)", "", ">= 17", MISSING, JAVA_ENABLES))

    # ---- Node
    npath, nv, _ = probe_version(["node"], ["--version"])
    rows.append(row("node", "node", vstr(nv), ">= 18", (OK if at_least(nv, (18,)) else OLD) if nv else MISSING,
                    "ports/node, ports/js, the Flowise and playground tests", path=npath))
    mpath, mv, _ = probe_version(["npm"], ["--version"])
    rows.append(row("npm", "npm", vstr(mv), "any", OK if mv else MISSING, "`npm test` in ports/node; `npm pack` for dist",
                    install_key="node", detail="" if mv else "without npm the tests run with `node --test` and dist has no npm tarballs", path=mpath))

    # ---- Go
    gpath, gv, _ = probe_version(["go"], ["version"], r"go version go([0-9.]+)")
    rows.append(row("go", "go", vstr(gv), ">= 1.21", (OK if at_least(gv, (1, 21)) else OLD) if gv else MISSING,
                    "ports/go, the cross-compiled dist binaries", path=gpath))

    # ---- PHP and its extensions
    ppath, pv, _ = probe_version(["php"], ["-r", "echo PHP_VERSION;"])
    if pv:
        _, mods = out_of([ppath, "-m"])
        loaded = set(m.strip().lower() for m in mods.splitlines())
        need = ["sodium", "openssl", "json", "mbstring"]
        lacking = [m for m in need if m not in loaded]
        st = OLD if not at_least(pv, (8, 1)) else (PARTIAL if lacking else OK)
        det = ("missing extensions: " + ", ".join(lacking)) if lacking else ""
        if "pcntl" not in loaded and not IS_WINDOWS:
            det = (det + "; " if det else "") + "optional pcntl is absent (the daemon then cannot stop cleanly on SIGTERM)"
        rows.append(row("php", "php + sodium, openssl, json, mbstring", vstr(pv), ">= 8.1", st, "ports/php", detail=det, path=ppath))
    else:
        rows.append(row("php", "php + sodium, openssl, json, mbstring", "", ">= 8.1", MISSING, "ports/php"))

    # ---- Rust
    rpath, rv, _ = probe_version(["rustc"], ["--version"], r"rustc ([0-9.]+)")
    capath, cav, _ = probe_version(["cargo"], ["--version"], r"cargo ([0-9.]+)")
    if rv and cav:
        st = OK if at_least(rv, (1, 89)) else OLD
        rows.append(row("rust", "cargo + rustc", vstr(rv), ">= 1.89", st, "ports/rust (real Cedar, HTTP and MCP proxy, C ABI, `bundle compile`)",
                        detail="the first build downloads crates from crates.io", path=capath))
    else:
        rows.append(row("rust", "cargo + rustc", vstr(rv or cav), ">= 1.89", PARTIAL if (rv or cav) else MISSING,
                        "ports/rust (real Cedar, HTTP and MCP proxy, C ABI, `bundle compile`)",
                        detail="only one of cargo and rustc is on PATH" if (rv or cav) else ""))

    # ---- C compiler
    names = ["cc", "gcc", "clang"] + (["cl"] if IS_WINDOWS else [])
    ccpath = next((which(n) for n in names if which(n)), None)
    ccline = ""
    if ccpath:
        _, text = out_of([ccpath] if os.path.basename(ccpath).lower().startswith("cl") else [ccpath, "--version"])
        ccline = next((l.strip() for l in text.splitlines() if l.strip()), "")
    ccv = vtuple(re.sub(r"^.*?\)\s*", "", ccline)) or vtuple(ccline)
    rows.append(row("cc", "C compiler (cc / gcc / clang" + (" / cl" if IS_WINDOWS else "") + ")", vstr(ccv) if ccpath else "", "any",
                    OK if ccpath else MISSING, "the C ABI check of ports/rust" + ("; MSVC is also what Rust links with" if IS_WINDOWS else ""),
                    path=ccpath, detail="the C ABI check is not run on Windows (test_all.ps1 skips it)" if IS_WINDOWS else ""))

    # ---- Docker
    dpath, dv, _ = probe_version(["docker"], ["--version"], r"version ([0-9.]+)")
    compose_v, daemon = None, False
    if dpath:
        s, text = out_of([dpath, "compose", "version", "--short"])
        compose_v = vtuple(text) if s == 0 else None
        s, text = out_of([dpath, "info", "--format", "{{.ServerVersion}}"], timeout=15)
        daemon = s == 0 and bool(vtuple(text))
    if dpath and compose_v and daemon:
        dst, ddet = OK, ""
    elif dpath:
        dst = PARTIAL
        ddet = "; ".join(x for x in ("" if compose_v else "the compose plugin is missing", "" if daemon else "no Docker daemon answers (not running, or no permission)") if x)
    else:
        dst, ddet = MISSING, ""
    rows.append(row("docker", "docker + compose", (vstr(dv) + ((" / compose " + vstr(compose_v)) if compose_v else "")) if dv else "", "compose v2",
                    dst, "make docker-build, make docker-test (docker/)", detail=ddet, path=dpath))

    # ---- PostgreSQL
    psql, pgctl = find_pg("psql"), find_pg("pg_ctl")
    pgv = None
    if pgctl or psql:
        _, text = out_of([pgctl or psql, "--version"])
        pgv = vtuple(re.sub(r"^.*?\)\s*", "", text.strip())) or vtuple(text)
    if pgctl:
        pst, pdet = OK, ("" if which("pg_ctl") else "pg_ctl found outside PATH: " + pgctl)
    elif psql:
        pst, pdet = PARTIAL, "only the client (psql) is here: the live upstream suite needs a server (pg_ctl, initdb) or SD_PG_DSN"
    else:
        pst, pdet = MISSING, "or attach to a running server with SD_PG_DSN"
    rows.append(row("postgres", "PostgreSQL (pg_ctl, initdb, psql)", vstr(pgv), "any", pst, "live/run.sh upstream (a real database behind the company API)",
                    detail=pdet, path=pgctl or psql))

    # ---- shells
    pwpath, pwv, _ = probe_version(["pwsh"], ["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
    if not pwv and IS_WINDOWS:
        pwpath, pwv, _ = probe_version(["powershell"], ["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
    rows.append(row("powershell", "PowerShell (pwsh / powershell)", vstr(pwv), ">= 5.1", (OK if at_least(pwv, (5, 1)) else OLD) if pwv else MISSING,
                    "bootstrap.ps1, make.ps1, test_all.ps1" + ("" if IS_WINDOWS else " (only needed on Windows)"), path=pwpath))
    bpath = which("bash")
    bv = None
    if bpath:
        _, text = out_of([bpath, "--version"])
        bv = vtuple(text)
    rows.append(row("bash", "bash", vstr(bv), "any", OK if bv else MISSING,
                    "bootstrap.sh, test_all.sh, ports/conformance/run.sh, live/*.sh" + (" (on Windows the .ps1 scripts replace them)" if IS_WINDOWS else ""), path=bpath))
    return rows


def usable(rows, key):
    r = next((x for x in rows if x["key"] == key), None)
    return bool(r) and r["status"] == OK


def components(rows, root=ROOT):
    """What each part of the repository needs, and whether it will run here.
    -> list of {name, runs, reason}"""
    u = lambda k: usable(rows, k)
    get = lambda k: next((x for x in rows if x["key"] == k), {"status": MISSING, "found": "", "detail": ""})
    why = lambda k: "%s: %s%s" % (get(k).get("tool", k), get(k)["status"], (" (" + get(k)["detail"] + ")") if get(k).get("detail") else "")
    py = u("python") and u("venv")
    out = []

    def add(name, runs, reason=""):
        out.append({"name": name, "runs": bool(runs), "reason": "" if runs else reason})

    add("reference (src/, tests/, harness/)", py, "needs Python 3.10+ with the venv module")
    add("ports/java", py and u("java"), why("java"))
    add("ports/node", py and u("node"), why("node"))
    add("ports/js (REST client)", py and u("node"), why("node"))
    add("ports/go", py and u("go"), why("go"))
    add("ports/php", py and u("php"), why("php"))
    add("ports/rust", py and u("rust"), why("rust"))
    add("ports/rust C ABI check", py and u("rust") and u("cc") and not IS_WINDOWS,
        "not run on Windows" if IS_WINDOWS else (why("rust") if not u("rust") else why("cc")))
    jv = vtuple(get("java")["found"])
    attach_kc = bool(os.environ.get("SD_KEYCLOAK_URL"))
    present = lambda rel: os.path.isfile(os.path.join(root, *rel.split("/")))
    if not present("live/idp/run.sh"):
        add("live/idp (real Keycloak)", False, "live/idp/run.sh is not in this checkout")
    elif IS_WINDOWS:
        add("live/idp (real Keycloak)", False, "a bash script: run it under WSL or Linux")
    else:
        add("live/idp (real Keycloak)", py and (attach_kc or (bool(which("java")) and at_least(jv, (17,)))),
            "needs Java 17+ to start Keycloak, or SD_KEYCLOAK_URL to attach to one")
    if not present("live/run.sh"):
        for n in ("live upstream (PostgreSQL)", "live boundary (network namespace)", "live load"):
            add(n, False, "live/run.sh is not in this checkout")
    elif IS_WINDOWS:
        for n in ("live upstream (PostgreSQL)", "live boundary (network namespace)", "live load"):
            add(n, False, "a bash script: run it under WSL or Linux")
    else:
        add("live upstream (PostgreSQL)", py and (bool(os.environ.get("SD_PG_DSN")) or get("postgres")["status"] == OK),
            "needs a PostgreSQL server (pg_ctl, initdb) or SD_PG_DSN")
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        add("live boundary (network namespace)", py and sys.platform.startswith("linux") and is_root,
            "Linux only" if not sys.platform.startswith("linux") else "needs root: sudo -E live/run.sh boundary")
        add("live load", py, "")
    add("docker targets (docker/)", u("docker"), why("docker"))
    return out


# --------------------------------------------------------------------------- output

def decorate(rows, pm):
    for r in rows:
        cmds, verified, note = ([], True, "") if r["install_key"] == "-" else install_commands(r["install_key"], pm)
        r["install"] = cmds
        r["install_verified"] = verified
        r["install_note"] = note
    return rows


STATUS_WORD = {OK: "OK", OLD: "TOO OLD", MISSING: "MISSING", PARTIAL: "INCOMPLETE"}


def install_text(r):
    if r["status"] == OK and not r.get("_show_all"):
        return ""
    if not r["install"]:
        return r["install_note"] or ""
    text = " && ".join(as_run(c) if r.get("_as_run") else c for c in r["install"])
    if not r["install_verified"]:
        text += "   [name not verified]"
    return text


def print_table(rows, comps, pm, stream=sys.stdout):
    w = stream.write
    w("SmartDelegate doctor: %s %s, %s; install commands for: %s\n\n" % (platform.system(), platform.release(), platform.machine(), pm))
    head = ("tool", "found", "required", "status", "enables")
    lines = [(r["tool"], r["found"] or "-", r["required"], STATUS_WORD[r["status"]] + ("" if r["optional"] else " *"), r["enables"]) for r in rows]
    widths = [max(len(x[i]) for x in [head] + lines) for i in range(4)]
    fmt = "  ".join("%%-%ds" % n for n in widths) + "  %s\n"
    w(fmt % head)
    w(fmt % (tuple("-" * n for n in widths) + ("-" * 7,)))
    for line in lines:
        w(fmt % line)
    w("  * required; everything else is optional and its part is skipped when absent\n")
    todo = [r for r in rows if r["status"] != OK]
    if todo:
        w("\nTo install what is missing (%s):\n" % pm)
        shown = set()
        for r in todo:
            w("  %-22s %s\n" % (r["key"] + ":", r["detail"] or STATUS_WORD[r["status"]].lower()))
            if r["install_key"] == "-" or (r["key"] == "docker" and r["found"]):
                continue        # nothing to install: pip does it, or Docker is here and only its daemon is not
            if r["install_key"] in shown:
                w("      (installed together with %s, above)\n" % r["install_key"])
                continue
            shown.add(r["install_key"])
            for c in r["install"]:
                w("      %s%s\n" % (as_run(c) if pm == package_manager() else c, "" if r["install_verified"] else "    [package name not verified]"))
            if r["install_note"]:
                w("      note: %s\n" % r["install_note"])
            if not r["install"] and not r["install_note"]:
                w("      (no package for this platform is listed)\n")
    notes = [r for r in rows if r["status"] == OK and r["detail"]]
    if notes:
        w("\nNotes:\n")
        for r in notes:
            w("  %-22s %s\n" % (r["key"] + ":", r["detail"]))
    w("\nWhat will run here:\n")
    for c in comps:
        w("  %-4s %s%s\n" % ("RUN" if c["runs"] else "SKIP", c["name"], "" if c["runs"] else "  (" + c["reason"] + ")"))
    stream.flush()


def print_markdown(rows, pm, stream=sys.stdout):
    w = stream.write
    w("| Tool | Required | Enables | Install (%s) |\n|---|---|---|---|\n" % pm)
    for r in rows:
        if r["install_key"] == "-":
            inst = "`pip install -e .` (the bootstrap does it)"
        elif r["install"]:
            inst = "<br>".join("`%s`" % c.replace("|", "\\|") for c in r["install"])
            if not r["install_verified"]:
                inst += " (name not verified)"
        else:
            inst = r["install_note"] or "-"
        w("| %s%s | %s | %s | %s |\n" % (r["tool"], "" if r["optional"] else " **(required)**", r["required"], r["enables"], inst))
    stream.flush()


# --------------------------------------------------------------------------- install

def install(rows, pm, only, dry_run):
    """Runs the install commands of every row that is not OK. Each command is
    printed first. -> number of commands that failed"""
    if pm == "other":
        print("doctor: no supported package manager here (winget, brew, apt-get, dnf); install by hand", file=sys.stderr)
        return 1
    manager = {"windows": "winget", "macos": "brew", "apt": "apt-get", "dnf": "dnf"}[pm]
    if not which(manager):
        print("doctor: %s is not on PATH; cannot install anything" % manager, file=sys.stderr)
        return 1
    failed, done = 0, set()
    for r in rows:
        key = r["install_key"]
        if r["status"] == OK or key == "-" or key in done or (only and r["key"] not in only and key not in only):
            continue
        if r["key"] == "docker" and r["found"]:
            print("doctor: docker is installed; what is missing: %s. Nothing to install." % r["detail"])
            continue
        done.add(key)
        if not r["install"]:
            print("doctor: %s: nothing to run on this platform. %s" % (r["key"], r["install_note"]))
            continue
        for c in r["install"]:
            cmd = as_run(c)
            if cmd.startswith("sudo "):
                print("doctor: the next command uses sudo and may ask for your password")
            print("+ " + cmd)
            sys.stdout.flush()
            if dry_run:
                continue
            try:
                status = subprocess.call(cmd, shell=True, timeout=1800)
            except subprocess.TimeoutExpired:
                status = 124
            if status != 0:
                print("doctor: that command failed (exit %s); continuing" % status, file=sys.stderr)
                failed += 1
                break
        if r["install_note"]:
            print("  note: " + r["install_note"])
    return failed


def main(argv=None):
    ap = argparse.ArgumentParser(prog="doctor.py", description="Detect the toolchains SmartDelegate can use and say what each enables.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--markdown", action="store_true", help="the requirements table as Markdown")
    ap.add_argument("--platform", choices=["windows", "macos", "apt", "dnf"], help="show another platform's install commands")
    ap.add_argument("--require", default="", help="comma-separated rows that must be usable (exit 1 otherwise), e.g. java,node,go,php,rust")
    ap.add_argument("--install", action="store_true", help="install what is missing with the package manager (prints each command first)")
    ap.add_argument("--only", default="", help="with --install: only these rows")
    ap.add_argument("--dry-run", action="store_true", help="with --install: print the commands, run nothing")
    ap.add_argument("--root", default=ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    pm = package_manager(a.platform)
    rows = decorate(check_all(a.root), pm)
    if a.install:
        if a.platform:
            print("doctor: --install installs for this machine; --platform is for looking only", file=sys.stderr)
            return 2
        only = set(x for x in a.only.split(",") if x)
        failed = install(rows, pm, only, a.dry_run)
        if failed:
            print("doctor: %d install command(s) failed" % failed, file=sys.stderr)
        elif not any(r["status"] != OK and r["install_key"] != "-" and (not only or r["key"] in only or r["install_key"] in only) for r in rows):
            print("doctor: nothing to install: every toolchain asked for is here")
        print("doctor: run `python scripts/doctor.py` to see the result (a new shell may be needed for PATH changes)")
        return 1 if failed else 0
    comps = components(rows, a.root)
    reference_ok = usable(rows, "python") and usable(rows, "venv")
    wanted = [x for x in a.require.split(",") if x]
    unknown = [x for x in wanted if not any(r["key"] == x for r in rows)]
    if unknown:
        print("doctor: unknown row(s) in --require: %s (rows: %s)" % (", ".join(unknown), ", ".join(r["key"] for r in rows)), file=sys.stderr)
        return 2
    lacking = [x for x in wanted if not usable(rows, x)]

    if a.json:
        json.dump({"platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "package_manager": pm},
                   "reference_ok": reference_ok, "tools": rows, "components": comps,
                   "skipped": [c["name"] for c in comps if not c["runs"]], "required_but_unusable": lacking},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif a.markdown:
        print_markdown(rows, pm)
    else:
        print_table(rows, comps, pm)
        if not reference_ok:
            print("\ndoctor: the reference needs Python 3.10+ with the venv module; nothing can be built or tested without it", file=sys.stderr)
        if lacking:
            print("\ndoctor: required by --require but not usable: " + ", ".join(lacking), file=sys.stderr)
    return 0 if reference_ok and not lacking else 1


if __name__ == "__main__":
    sys.exit(main())
