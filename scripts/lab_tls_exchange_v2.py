"""Isolated TLS controls with a measured post-handshake size/pacing contrast.

The traffic generator completes TLS handshakes only inside a private lab. The
passive analyser reads PCAP headers and never decrypts application records.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import ssl
import time


HOST, CLIENT, PORT = "10.39.0.1", "10.39.0.2", 443
BASELINE, RARE_BENIGN, CHANGED = 110, 4, 8
TOTAL = BASELINE + RARE_BENIGN + CHANGED


def contexts(server: bool, cert: Path | None = None, key: Path | None = None):
    if server:
        result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        result.load_cert_chain(certfile=cert, keyfile=key)
        return result
    common = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    common.check_hostname = False
    common.verify_mode = ssl.CERT_NONE
    common.minimum_version = common.maximum_version = ssl.TLSVersion.TLSv1_2
    common.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    rare_benign = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    rare_benign.check_hostname = False
    rare_benign.verify_mode = ssl.CERT_NONE
    rare_benign.minimum_version = rare_benign.maximum_version = ssl.TLSVersion.TLSv1_2
    rare_benign.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    changed = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    changed.check_hostname = False
    changed.verify_mode = ssl.CERT_NONE
    changed.minimum_version = changed.maximum_version = ssl.TLSVersion.TLSv1_3
    return common, rare_benign, changed


def server(cert: Path, key: Path) -> None:
    context = contexts(True, cert, key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(16)
        for index in range(TOTAL):
            connection, peer = listener.accept()
            if peer[0] != CLIENT:
                connection.close()
                raise RuntimeError("Non-lab TLS client contacted fixed endpoint")
            with connection:
                connection.settimeout(5)
                with context.wrap_socket(connection, server_side=True) as secure:
                    if index < BASELINE + RARE_BENIGN:
                        secure.recv(4096)
                        secure.sendall(b"ack")
                    else:
                        for _ in range(4):
                            if len(secure.recv(4096)) == 0:
                                raise RuntimeError("Changed session ended early")
                            time.sleep(.09)
                            secure.sendall(b"R" * 1250)


def client() -> None:
    common, rare_benign, changed = contexts(False)
    for index in range(TOTAL):
        if index < BASELINE:
            label, context = "baseline", common
        elif index < BASELINE + RARE_BENIGN:
            label, context = "rare-benign", rare_benign
        else:
            label, context = "paced-size-anomaly", changed
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.bind((CLIENT, 0))
            source_port = connection.getsockname()[1]
            connection.connect((HOST, PORT))
            with context.wrap_socket(connection, server_hostname="lab.test") as secure:
                if label == "paced-size-anomaly":
                    for _ in range(4):
                        secure.sendall(b"Q" * 1150)
                        if len(secure.recv(4096)) == 0:
                            raise RuntimeError("Changed session reply missing")
                        time.sleep(.09)
                else:
                    secure.sendall(b"ping")
                    secure.recv(4096)
            print(f"{index},{label},{source_port}", flush=True)
        time.sleep(.004)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    if args.mode == "server":
        if args.cert is None or args.key is None:
            raise SystemExit("Private lab certificate and key required")
        server(args.cert, args.key)
    else:
        client()


if __name__ == "__main__":
    main()
