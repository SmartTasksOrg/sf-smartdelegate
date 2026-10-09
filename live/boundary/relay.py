"""A byte relay between a TCP port and a Unix-domain socket. No parsing, no
buffering beyond one read: what one side sends, the other receives, including
half-finished requests.

    relay.py unix2tcp /path/to.sock 127.0.0.1:8182     listen on the Unix socket, connect to TCP
    relay.py tcp2unix 127.0.0.1:8182 /path/to.sock     listen on TCP, connect to the Unix socket

The boundary test uses the pair to carry the proxy, and nothing else, into a
network namespace: path-based Unix sockets belong to the file system, not to
a network namespace, so a socket file is a door the kernel lets through
while every interface, route and port of the host stays outside.
"""
from __future__ import annotations

import os
import socket
import sys
import threading

IDLE = 300.0    # seconds without a byte in either direction before a connection is dropped
MAX_CONNECTIONS = 256


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
            try:
                s.shutdown(how)
            except OSError:
                pass


def serve(listener: socket.socket, connect, stop: threading.Event | None = None) -> None:
    """Accept forever (or until `stop`); one thread pair per connection."""
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    listener.settimeout(0.5)
    while stop is None or not stop.is_set():
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if not slots.acquire(blocking=False):
            client.close()
            continue

        def handle(client=client):
            upstream = None
            try:
                client.settimeout(IDLE)
                upstream = connect()
                upstream.settimeout(IDLE)
                t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
                t.start()
                pump(client, upstream)
                t.join(timeout=IDLE)
            except OSError:
                pass
            finally:
                for s in (client, upstream):
                    try:
                        if s is not None:
                            s.close()
                    except OSError:
                        pass
                slots.release()

        threading.Thread(target=handle, daemon=True).start()


def tcp_listener(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(128)
    return s


def unix_listener(path: str, mode: int = 0o600) -> socket.socket:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        s.bind(path)
    finally:
        os.umask(old)
    os.chmod(path, mode)
    s.listen(128)
    return s


def unix_connector(path: str):
    def connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(path)
        return s
    return connect


def tcp_connector(host: str, port: int):
    return lambda: socket.create_connection((host, port), timeout=10)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3 or argv[0] not in ("unix2tcp", "tcp2unix"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[0] == "unix2tcp":
        host, _, port = argv[2].rpartition(":")
        listener, connect = unix_listener(argv[1]), tcp_connector(host, int(port))
    else:
        host, _, port = argv[1].rpartition(":")
        listener, connect = tcp_listener(host, int(port)), unix_connector(argv[2])
    print("relay ready", flush=True)
    try:
        serve(listener, connect)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
