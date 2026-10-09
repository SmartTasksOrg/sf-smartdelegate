"""The cell: run one command inside a network namespace whose only way out is
a relay to one Unix socket.

    unshare -n python3 cell.py --uds /root-only/proxy.sock --port 8182 --uid 65534 --gid 65534 \
            --workdir /private/dir --timeout 120 --env KEY=VALUE ... -- <agent command...>

Run as root, already inside the fresh namespace (`unshare -n`). It
  1. refuses to continue unless this namespace has no interface but `lo`
     (so a mistake in the caller cannot quietly run the agent on the host's network),
  2. brings `lo` up with an ioctl (no `ip` tool needed),
  3. listens on 127.0.0.1:<port> *of the namespace* and relays every
     connection to the Unix socket, whose other end is the SmartDelegate proxy,
  4. starts the agent as an unprivileged user with exactly the environment
     given by --env, in its private directory, and waits for it (kill by PID
     on timeout).

The relay stays in this root process. The agent's uid cannot open the Unix
socket (its directory is root-only), cannot join another namespace (setns
needs CAP_SYS_ADMIN) and has no capability at all.
"""
from __future__ import annotations

import argparse
import fcntl
import os
import socket
import struct
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay  # noqa: E402

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1


def interfaces() -> list:
    return sorted(name for _, name in socket.if_nameindex())


def loopback_up() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))
    finally:
        s.close()


def drop_privileges(uid: int, gid: int):
    def fn():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        os.umask(0o077)
    return fn


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uds", required=True)
    ap.add_argument("--port", type=int, default=8182)
    ap.add_argument("--uid", type=int, required=True)
    ap.add_argument("--gid", type=int, required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not command:
        ap.error("no agent command")
    names = interfaces()
    if names != ["lo"]:
        print(f"cell: this is not a fresh network namespace (interfaces: {names}); refusing to run the agent", file=sys.stderr)
        return 97
    if os.geteuid() != 0:
        print("cell: must start as root (it drops to --uid for the agent)", file=sys.stderr)
        return 97
    loopback_up()
    stop = threading.Event()
    listener = relay.tcp_listener("127.0.0.1", a.port)
    threading.Thread(target=relay.serve, args=(listener, relay.unix_connector(a.uds), stop), daemon=True).start()
    env = dict(kv.split("=", 1) for kv in a.env)
    proc = subprocess.Popen(command, env=env, cwd=a.workdir, stdin=subprocess.DEVNULL, preexec_fn=drop_privileges(a.uid, a.gid), close_fds=True)
    try:
        status = proc.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        status = 98
    stop.set()
    listener.close()
    return status


if __name__ == "__main__":
    sys.exit(main())
