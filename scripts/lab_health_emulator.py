from __future__ import annotations

import ipaddress
import socket
import sys
import time


SERVER = "10.34.1.1"
PORT = 18444
INTERVALS = (2, 6, 2, 6, 2, 6, 2, 6, 2, 6)


def validate() -> None:
    if SERVER != "10.34.1.1" or PORT != 18444 or not ipaddress.ip_address(SERVER).is_private:
        raise SystemExit("Refusing a non-lab health-check endpoint")


def serve() -> None:
    validate()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((SERVER, PORT))
        server.listen(8)
        for _ in range(11):
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                payload = connection.recv(512)
                connection.sendall(b"healthy:" + payload[:32])


def check() -> None:
    validate()
    for index in range(11):
        size = 8 if index % 2 == 0 else 180
        payload = (f"health:{index}:" + "x" * size).encode("ascii")
        with socket.create_connection((SERVER, PORT), timeout=5) as connection:
            connection.sendall(payload)
            connection.recv(128)
        if index < len(INTERVALS):
            time.sleep(INTERVALS[index])


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"server", "client"}:
        raise SystemExit("usage: lab_health_emulator.py server|client")
    serve() if sys.argv[1] == "server" else check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
