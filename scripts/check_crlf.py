#!/usr/bin/env python3
"""Does a checkout with Windows line endings break a bundle?

    python3 scripts/check_crlf.py            every engine that is installed
    python3 scripts/check_crlf.py -v         with each command and its answer

The bundle version hashes policies.json, entities.json, catalog.json and
roles.json with CRLF replaced by LF, and policies.json records the hash of
each .cedar source the same way (spec/PORTING.md, "Bundle"). So a bundle
whose files were rewritten with CRLF (git on Windows with core.autocrlf, or an
editor) must still load, keep its version, pass the `bundle_stale` check and
keep a valid signature. This script proves it for every installed engine:

  1. a copy of spec/conformance/bundle with LF and one with CRLF in every
     file: each engine loads both and reports one and the same policy_version
     (the CRLF copy has CRLF in policies/*.cedar too: no bundle_stale)
  2. the LF copy is signed, then converted to CRLF (bundle.sig.json as well):
     each engine verifies it with the public key
  3. the CRLF copy is signed ("signed on Windows"), then converted to LF:
     each engine verifies it
  4. control: one character of roles.json is changed in a signed copy; each
     engine must refuse it with bundle_signature
  5. the reference runs the bundle's own policy tests on the CRLF copy

.gitattributes makes git check every text file out with LF on every platform,
so 1 to 3 should never be needed; they are the second line of defence.

Python 3.8+, standard library. The engines are driven through their command
lines: the reference with the interpreter that runs this script (it needs
`cryptography`; use .venv's python), the others when their toolchain or
binary is there. The key pair is made in a temporary directory that is
removed at the end. Exit status: 0 no failure, 1 a failure, 2 nothing to run.
"""
from __future__ import print_function

import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
VERBOSE = "-v" in sys.argv[1:] or "--verbose" in sys.argv[1:]
TIMEOUT = 120


def P(*parts):
    return os.path.join(ROOT, *parts)


def engines(tmp):
    """-> ({name: command line}, {name: why it is skipped})"""
    found, skipped = {}, {}
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([P("src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    probe = subprocess.run([sys.executable, "-c", "import cryptography, smartdelegate"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    if probe.returncode == 0:
        found["python"] = [sys.executable, "-m", "sf_smartdelegate"]
    else:
        skipped["python"] = "%s cannot import cryptography (use .venv's python)" % sys.executable
    if shutil.which("node"):
        found["node"] = [shutil.which("node"), P("ports", "node", "bin", "cli.mjs")]
    else:
        skipped["node"] = "node is not installed"
    if shutil.which("php"):
        found["php"] = [shutil.which("php"), P("ports", "php", "bin", "smartdelegate-php")]
    else:
        skipped["php"] = "php is not installed"
    go_bin = P("build", "bin", "smartdelegate-go" + EXE)
    if os.path.isfile(go_bin):
        found["go"] = [go_bin]
    elif shutil.which("go"):
        out = os.path.join(tmp, "smartdelegate-go" + EXE)
        genv = dict(os.environ)
        genv.setdefault("GOTOOLCHAIN", "local")
        genv.setdefault("GOFLAGS", "-buildvcs=false")
        r = subprocess.run([shutil.which("go"), "build", "-o", out, "./cmd/smartdelegate-go"], cwd=P("ports", "go"), env=genv,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
        if r.returncode == 0:
            found["go"] = [out]
        else:
            skipped["go"] = "go build failed: " + r.stdout.decode("utf-8", "replace")[-200:]
    else:
        skipped["go"] = "go is not installed and build/bin/smartdelegate-go does not exist"
    rust = P("ports", "rust", "target", "release", "smartdelegate" + EXE)
    if os.path.isfile(rust):
        found["rust"] = [rust]
    else:
        skipped["rust"] = "ports/rust/target/release/smartdelegate does not exist (cargo build --release)"
    jar = P("ports", "java", "build", "smartdelegate.jar")
    if not shutil.which("java"):
        skipped["java"] = "java is not installed"
    elif os.path.isfile(jar):
        found["java"] = [shutil.which("java"), "-Dfile.encoding=UTF-8", "-jar", jar]
    else:
        skipped["java"] = "ports/java/build/smartdelegate.jar does not exist (ports/java/build.sh)"
    return found, skipped, env


def call(cmd, args, env):
    """-> (exit status, parsed JSON or None, text)"""
    env = dict(env)
    env.pop("JAVA_TOOL_OPTIONS", None)        # its banner is not part of the answer
    try:
        r = subprocess.run(cmd + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, None, "no answer within %d s" % TIMEOUT
    out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    if VERBOSE:
        print("      $ " + " ".join(cmd + args))
        print("        exit %d %s" % (r.returncode, (out.strip() or err.strip()).replace("\n", " ")[:160]))
    try:
        return r.returncode, json.loads(out), out + err
    except ValueError:
        return r.returncode, None, out + err


def convert(src, dst, eol):
    """Copies a bundle directory, rewriting the line ends of every file."""
    for d, _, files in os.walk(src):
        target = os.path.join(dst, os.path.relpath(d, src))
        os.makedirs(target, exist_ok=True)
        for name in files:
            with open(os.path.join(d, name), "rb") as f:
                data = f.read().replace(b"\r\n", b"\n")
            if eol == "crlf":
                data = data.replace(b"\n", b"\r\n")
            with open(os.path.join(target, name), "wb") as f:
                f.write(data)


def has_crlf(directory):
    n = 0
    for d, _, files in os.walk(directory):
        for name in files:
            with open(os.path.join(d, name), "rb") as f:
                n += b"\r\n" in f.read()
    return n


def config(tmp, name, bundle, public_key=None):
    path = os.path.join(tmp, name + ".json")
    cfg = {"bundle_dir": bundle, "state_dir": os.path.join(tmp, "state-" + name)}
    if public_key:
        cfg["bundle_public_key"] = public_key
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return path


def main():
    tmp = tempfile.mkdtemp(prefix="smartdelegate-crlf-")
    failures, results = [], []

    def check(engine, what, ok, detail=""):
        results.append((engine, what, ok))
        print("  %-6s %-4s %s%s" % (engine, "PASS" if ok else "FAIL", what, "" if ok else ": " + detail))
        if not ok:
            failures.append((engine, what, detail))

    try:
        found, skipped, env = engines(tmp)
        for name, why in sorted(skipped.items()):
            print("  %-6s SKIP %s" % (name, why))
        if not found:
            print("check_crlf: no engine can run here")
            return 2
        source = P("spec", "conformance", "bundle")
        lf, crlf = os.path.join(tmp, "lf"), os.path.join(tmp, "crlf")
        convert(source, lf, "lf")
        convert(source, crlf, "crlf")
        n_files = sum(len(f) for _, _, f in os.walk(crlf))
        print("bundle: %s; the CRLF copy has CRLF in %d of %d files" % (os.path.relpath(source, ROOT), has_crlf(crlf), n_files))
        assert has_crlf(lf) == 0 and has_crlf(crlf) > 0

        # 1. same version, no bundle_stale
        print("1. each engine loads the LF and the CRLF copy and reports the same policy_version")
        versions = {}
        for name, cmd in sorted(found.items()):
            s1, a, t1 = call(cmd, ["call", "info", "--config", config(tmp, name + "-lf", lf)], env)
            s2, b, t2 = call(cmd, ["call", "info", "--config", config(tmp, name + "-crlf", crlf)], env)
            ok = bool(a and b and a.get("ok") and b.get("ok") and a.get("policy_version") == b.get("policy_version"))
            versions[name] = (a or {}).get("policy_version")
            check(name, "LF and CRLF copies load with one policy_version", ok, (t2 if not (b and b.get("ok")) else t1).strip()[-200:])
        distinct = set(v for v in versions.values() if v)
        check("all", "every engine reports the same policy_version (%s...)" % (sorted(distinct)[0][:16] if distinct else "?"), len(distinct) == 1, str(versions))

        # the key pair: made by the first engine that can, in the temporary directory
        signer = "python" if "python" in found else sorted(found)[0]
        prefix = os.path.join(tmp, "signing")
        s, _, t = call(found[signer], ["bundle", "keygen", prefix], env)
        if s != 0 or not os.path.isfile(prefix + ".pub"):
            check(signer, "bundle keygen", False, t.strip()[-200:])
            return 1
        with open(prefix + ".pub", encoding="utf-8") as f:
            public = f.read().strip()

        def sign(directory):
            s_, _, t_ = call(found[signer], ["bundle", "sign", "--key", prefix + ".key", "--bundle", directory, "--state", os.path.join(tmp, "state-sign")], env)
            return s_ == 0 and os.path.isfile(os.path.join(directory, "bundle.sig.json")), t_

        # 2. signed with LF, checked out with CRLF
        print("2. signed with LF (by %s), then every file rewritten with CRLF: the signature still verifies" % signer)
        signed_lf = os.path.join(tmp, "signed-lf")
        convert(source, signed_lf, "lf")
        ok, t = sign(signed_lf)
        if not ok:
            check(signer, "bundle sign", False, t.strip()[-200:])
            return 1
        lf_to_crlf = os.path.join(tmp, "signed-lf-to-crlf")
        convert(signed_lf, lf_to_crlf, "crlf")
        for name, cmd in sorted(found.items()):
            s, a, t = call(cmd, ["call", "info", "--config", config(tmp, name + "-s1", lf_to_crlf, public)], env)
            check(name, "verifies the LF-signed bundle after conversion to CRLF", bool(a and a.get("ok") and a.get("bundle_signed_by")), t.strip()[-200:])

        # 3. signed with CRLF, checked out with LF
        print("3. signed with CRLF, then every file rewritten with LF: the signature still verifies")
        signed_crlf = os.path.join(tmp, "signed-crlf")
        convert(source, signed_crlf, "crlf")
        ok, t = sign(signed_crlf)
        if not ok:
            check(signer, "bundle sign on the CRLF copy", False, t.strip()[-200:])
            return 1
        crlf_to_lf = os.path.join(tmp, "signed-crlf-to-lf")
        convert(signed_crlf, crlf_to_lf, "lf")
        for name, cmd in sorted(found.items()):
            s, a, t = call(cmd, ["call", "info", "--config", config(tmp, name + "-s2", crlf_to_lf, public)], env)
            s3, a3, t3 = call(cmd, ["call", "info", "--config", config(tmp, name + "-s3", signed_crlf, public)], env)
            good = bool(a and a.get("ok") and a.get("bundle_signed_by") and a3 and a3.get("ok") and a3.get("bundle_signed_by"))
            check(name, "verifies the CRLF-signed bundle, as signed and after conversion to LF", good, (t + t3).strip()[-200:])

        # 4. control: a real change is still refused
        print("4. control: one character of roles.json changed in the signed CRLF copy: refused")
        tampered = os.path.join(tmp, "tampered")
        convert(lf_to_crlf, tampered, "crlf")
        roles = os.path.join(tampered, "roles.json")
        with open(roles, "rb") as f:
            data = f.read()
        assert b"support-agent" in data
        with open(roles, "wb") as f:
            f.write(data.replace(b"support-agent", b"support-agenT", 1))
        for name, cmd in sorted(found.items()):
            s, a, t = call(cmd, ["call", "info", "--config", config(tmp, name + "-t", tampered, public)], env)
            refused = s != 0 and "bundle_signature" in t
            check(name, "refuses the changed bundle with bundle_signature", refused, "exit %s: %s" % (s, t.strip()[-160:]))

        # 5. the bundle's own tests on the CRLF copy
        if "python" in found:
            print("5. the reference runs the bundle's policy tests on the CRLF copy")
            s, _, t = call(found["python"], ["policy", "test", "--bundle", crlf, "--state", os.path.join(tmp, "state-pt")], env)
            check("python", "policy test on the CRLF copy", s == 0, t.strip()[-200:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for r in results if r[2])
    print("summary: pass=%d fail=%d skipped_engines=%d" % (passed, len(failures), len(skipped)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
