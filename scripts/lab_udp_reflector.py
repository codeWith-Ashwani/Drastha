"""Fixed-endpoint UDP amplification-shape server for the isolated SIH lab.

This is a controlled responder, not an Internet-facing reflector or a claim
that spoofing occurred. The capture is analysed passively after generation.
"""
from __future__ import annotations

import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="10.36.0.1")
    parser.add_argument("--port", type=int, default=53)
    args = parser.parse_args()
    if args.bind != "10.36.0.1" or args.port != 53:
        raise SystemExit("Refusing to bind outside the fixed private SIH lab endpoint")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((args.bind, args.port))
        while True:
            _payload, peer = server.recvfrom(512)
            print(f"request from {peer[0]}:{peer[1]}", flush=True)
            server.sendto(b"R" * 2048, peer)


if __name__ == "__main__":
    main()
