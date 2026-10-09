#!/usr/bin/env python3
"""One-shot set-up of the identity provider side of docker/docker-compose.yml.

    SD_KEYCLOAK_URL=http://keycloak:8080 SD_KEYCLOAK_ADMIN=... SD_KEYCLOAK_ADMIN_PASSWORD=... \
        python docker/idp_init.py --base docker/compose-daemon.json --out /idp-config

1. Creates (or repairs) the test realm in Keycloak with live/idp/provision.py,
   the provisioning the live identity-provider suite uses. Its record, which
   holds test passwords and client secrets, stays in SD_KEYCLOAK_CACHE; it is
   NOT written to --out.
2. Writes into --out, the directory the daemon mounts read-only:
     jwks.json            GET <url>/realms/<realm>/protocol/openid-connect/certs
     smartdelegate.json   the --base config plus the `idp` section the operator
                          guidance of live/idp/README.md asks for: issuer (the
                          exact `iss` of the tokens), audience `sd-engine` (the
                          engine checks `azp` against it), `jwks_file`,
                          user_claim preferred_username, groups_claim groups
                          and the group_map from the provisioning record.
   Neither file holds a secret: a JWKS is public keys.

    python docker/idp_init.py --jwks-only --out /idp-config

   only rewrites jwks.json. That is step two of a key rotation: new key
   passive in Keycloak -> this -> POST /v1/admin/reload on the daemon (admin
   key) -> make the key active. The engine re-reads `idp.jwks_file` on reload;
   no restart.

Python 3.10+, standard library, plus live/idp/kc.py and provision.py of this
repository. Run on Linux against a real Keycloak 26.0.7 outside a container
(docs/BUILD.md); never run in a container.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)             # read by the daemon's uid, which is not ours
    os.replace(tmp, path)


def fetch_jwks(url, realm):
    last = None
    for _ in range(30):
        try:
            with urllib.request.urlopen("%s/realms/%s/protocol/openid-connect/certs" % (url, realm), timeout=10) as r:
                jwks = json.loads(r.read().decode("utf-8"))
            if isinstance(jwks.get("keys"), list) and jwks["keys"]:
                return jwks
            last = "the JWKS has no keys"      # the engine would accept it on reload and then refuse every sign-in
        except (OSError, ValueError) as e:
            last = str(e)
        time.sleep(2)
    raise SystemExit("idp_init: no usable JWKS from %s (realm %s): %s" % (url, realm, last))


def main():
    ap = argparse.ArgumentParser(description="Provision the test realm and write the daemon's idp config and JWKS file.")
    ap.add_argument("--out", required=True, help="directory for jwks.json and smartdelegate.json")
    ap.add_argument("--base", help="the daemon config without the idp section (docker/compose-daemon.json)")
    ap.add_argument("--jwks-only", action="store_true", help="only rewrite jwks.json (key rotation)")
    ap.add_argument("--audience", default="sd-engine", help="the engine's client in the realm (default sd-engine)")
    ap.add_argument("--public-url", help="the base URL users sign in through, when it is not SD_KEYCLOAK_URL; it becomes the issuer")
    a = ap.parse_args()

    url = os.environ.get("SD_KEYCLOAK_URL", "").rstrip("/")
    realm = os.environ.get("SD_KEYCLOAK_REALM", "kestrel")
    if not url:
        raise SystemExit("idp_init: set SD_KEYCLOAK_URL (and SD_KEYCLOAK_ADMIN, SD_KEYCLOAK_ADMIN_PASSWORD)")
    os.makedirs(a.out, exist_ok=True)

    if a.jwks_only:
        jwks = fetch_jwks(url, realm)
        write(os.path.join(a.out, "jwks.json"), json.dumps(jwks))
        print("idp_init: wrote jwks.json (%d key(s)). Now: POST /v1/admin/reload on the daemon with the admin key." % len(jwks["keys"]))
        return 0
    if not a.base:
        raise SystemExit("idp_init: --base is needed unless --jwks-only")

    status = subprocess.call([sys.executable, os.path.join(ROOT, "live", "idp", "provision.py")], timeout=1800)
    if status != 0:
        raise SystemExit("idp_init: live/idp/provision.py exited with %d" % status)
    from live.idp import kc
    with open(kc.provision_file(), encoding="utf-8") as f:
        record = json.load(f)

    jwks = fetch_jwks(url, realm)
    with open(a.base, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["idp"] = {
        "issuer": "%s/realms/%s" % ((a.public_url or url).rstrip("/"), realm),
        "audience": a.audience,
        "jwks_file": "jwks.json",                 # relative to this config file; re-read on POST /v1/admin/reload
        "user_claim": "preferred_username",       # only while "Edit username" is off in the realm
        "groups_claim": "groups",                 # the client's Group Membership mapper, full path on
        "group_map": record["group_map"],         # Keycloak group path -> SmartDelegate group
    }
    write(os.path.join(a.out, "jwks.json"), json.dumps(jwks))
    write(os.path.join(a.out, "smartdelegate.json"), json.dumps(cfg, indent=1))
    print("idp_init: realm %s provisioned; wrote jwks.json (%d key(s)) and smartdelegate.json (issuer %s, audience %s, %d mapped groups) to %s"
          % (realm, len(jwks["keys"]), cfg["idp"]["issuer"], a.audience, len(record["group_map"]), a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
