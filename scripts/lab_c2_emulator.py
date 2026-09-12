from __future__ import annotations

import argparse
import ipaddress
import socket
import time


LAB_SERVER = "10.34.0.1"
LAB_PORT = 18443


def ensure_lab_target(address: str, port: int) -> None:
    parsed = ipaddress.ip_address(address)
    if address != LAB_SERVER or port != LAB_PORT or not parsed.is_private:
        raise SystemExit("Refusing to contact anything outside the fixed Sprint 34 lab endpoint")


def serve(count: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((LAB_SERVER, LAB_PORT))
        server.listen(8)
        for _ in range(count):
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                message = connection.recv(64)
                connection.sendall(b"ack:" + message[:24])


def beacon(count: int, interval: float) -> None:
    ensure_lab_target(LAB_SERVER, LAB_PORT)
    for index in range(count):
        with socket.create_connection((LAB_SERVER, LAB_PORT), timeout=5) as connection:
            connection.sendall(f"status:{index:02d}".encode("ascii"))
            connection.recv(64)
        if index + 1 < count:
            time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated deterministic C2 timing emulator")
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--profile", choices=("sprint34", "gate2"), default="sprint34")
    parser.add_argument("--count", type=int, default=11)
    parser.add_argument("--interval", type=float, default=3.0)
    args = parser.parse_args()
    expected = (11, 3.0) if args.profile == "sprint34" else (13, 2.5)
    if (args.count, args.interval) != expected:
        raise SystemExit(f"{args.profile} lab profile requires {expected[0]} beacons at a {expected[1]}-second interval")
    serve(args.count) if args.mode == "server" else beacon(args.count, args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
