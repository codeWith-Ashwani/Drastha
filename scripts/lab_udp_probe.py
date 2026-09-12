"""Valid UDP client for the fixed private amplification-shape lab."""
from __future__ import annotations

import socket
import time


def main() -> None:
    for index in range(16):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.bind(("10.36.0.2", 43000 + index))
            client.sendto(b"Q", ("10.36.0.1", 53))
            payload, peer = client.recvfrom(4096)
            if peer != ("10.36.0.1", 53) or len(payload) != 2048:
                raise SystemExit("Unexpected isolated responder")
            print(f"valid response {index + 1}: {len(payload)} bytes", flush=True)
        time.sleep(0.02)


if __name__ == "__main__":
    main()
