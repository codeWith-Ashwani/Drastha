from __future__ import annotations

import argparse
import ipaddress
import socket
import threading


ALLOWED_BIND_ADDRESSES = {"127.0.0.1", "10.34.0.1"}


def serve_connection(connection: socket.socket) -> None:
    with connection:
        connection.settimeout(180)
        received = bytearray()
        try:
            while len(received) <= 4096:
                chunk = connection.recv(256)
                if not chunk:
                    return
                received.extend(chunk)
                if b"\r\n\r\n" in received:
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    )
                    return
        except (TimeoutError, ConnectionError, OSError):
            return


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only HTTP sink for the Sprint 34 lab")
    parser.add_argument("--bind", default="10.34.0.1")
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    if args.bind not in ALLOWED_BIND_ADDRESSES or not ipaddress.ip_address(args.bind).is_private:
        raise SystemExit("Refusing to bind outside the fixed loopback/private Sprint 34 lab")
    if args.port != 18081:
        raise SystemExit("Refusing a non-lab HTTP port")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.bind, args.port))
        server.listen(128)
        while True:
            connection, _ = server.accept()
            threading.Thread(target=serve_connection, args=(connection,), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
