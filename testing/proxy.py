#!/usr/bin/env python3
"""
Minimal HTTP CONNECT proxy for Freewire test Configuration 1.

Simulates a captive portal that exposes a CONNECT proxy on port 443.
Run on the gateway machine (see README "Config 1 does not work on a single machine"):

    sudo python3 proxy.py [--port 443] [--bind 0.0.0.0]

NOTE ON THE SPEC: the proxy.py listing in captive-portal-testing-guide.md
does not work. Its relay threads target

    lambda a, b: (b.send(a.recv(4096)) for _ in iter(int, 1))

which builds a generator and never iterates it, so no bytes are ever
relayed. The CONNECT returns 200 and the tunnel then hangs. This version
relays properly, handles half-close, and logs each tunnel.
"""

import argparse
import socket
import sys
import threading

BUFSIZE = 65536
CONNECT_TIMEOUT = 10


def relay(src: socket.socket, dst: socket.socket) -> None:
    """Pump bytes one way until EOF, then half-close the far side."""
    try:
        while True:
            data = src.recv(BUFSIZE)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, addr) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    remote = None
    try:
        client.settimeout(CONNECT_TIMEOUT)
        request = b""
        # Read until end of headers — CONNECT may arrive split across packets.
        while b"\r\n\r\n" not in request:
            chunk = client.recv(BUFSIZE)
            if not chunk:
                return
            request += chunk
            if len(request) > 32768:
                client.sendall(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                return

        line = request.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()

        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            print(f"[{peer}] rejected non-CONNECT: {line!r}", flush=True)
            return

        target = parts[1]
        host, _, port_s = target.rpartition(":")
        if not host:
            host, port = target, 443
        else:
            try:
                port = int(port_s)
            except ValueError:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return

        try:
            remote = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            print(f"[{peer}] 502 {host}:{port} ({e})", flush=True)
            return

        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        print(f"[{peer}] 200 tunnel -> {host}:{port}", flush=True)

        # Blocking relays; no timeout once the tunnel is up.
        client.settimeout(None)
        remote.settimeout(None)

        t = threading.Thread(target=relay, args=(remote, client), daemon=True)
        t.start()
        relay(client, remote)
        t.join()
        print(f"[{peer}] closed {host}:{port}", flush=True)

    except OSError as e:
        print(f"[{peer}] error: {e}", flush=True)
    finally:
        for s in (client, remote):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.bind, args.port))
    except PermissionError:
        print(f"Port {args.port} needs root. Try: sudo python3 {sys.argv[0]}",
              file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Cannot bind {args.bind}:{args.port} — {e}", file=sys.stderr)
        return 1

    srv.listen(50)
    print(f"CONNECT proxy listening on {args.bind}:{args.port} (Ctrl-C to stop)",
          flush=True)

    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle, args=(client, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
