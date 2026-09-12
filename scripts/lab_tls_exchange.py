"""Fixed private-link TLS sessions for passive metadata validation.

The generator may complete handshakes inside the isolated lab; Drastha's
analyser never initiates a handshake or decrypts the resulting capture.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import ssl
import time


HOST = "10.37.0.1"
CLIENT = "10.37.0.2"
PORT = 443
BASELINE = 110
RARE = 6


def server(cert: Path, key: Path) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(16)
        for index in range(BASELINE + RARE):
            connection, peer = listener.accept()
            if peer[0] != CLIENT:
                connection.close()
                raise RuntimeError("Non-lab TLS client contacted fixed endpoint")
            with connection:
                connection.settimeout(5)
                if index >= BASELINE:
                    time.sleep(.12)
                with context.wrap_socket(connection, server_side=True) as secure:
                    secure.recv(2048)
                    secure.sendall(b"ack" if index < BASELINE else b"A" * 900)


def client() -> None:
    baseline = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    baseline.check_hostname = False
    baseline.verify_mode = ssl.CERT_NONE
    baseline.minimum_version = baseline.maximum_version = ssl.TLSVersion.TLSv1_2
    baseline.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    rare = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    rare.check_hostname = False
    rare.verify_mode = ssl.CERT_NONE
    rare.minimum_version = rare.maximum_version = ssl.TLSVersion.TLSv1_3
    for index in range(BASELINE + RARE):
        label = "benign" if index < BASELINE else "anomalous-lab"
        context = baseline if index < BASELINE else rare
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.bind((CLIENT, 0))
            source_port = connection.getsockname()[1]
            connection.connect((HOST, PORT))
            with context.wrap_socket(connection, server_hostname="lab.test") as secure:
                secure.sendall(b"ping" if index < BASELINE else b"P" * 1200)
                secure.recv(2048)
            print(f"{index},{label},{source_port}", flush=True)
        time.sleep(.005 if index < BASELINE else .15)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    if args.mode == "server":
        if args.cert is None or args.key is None:
            raise SystemExit("Private lab certificate and key required for server")
        server(args.cert, args.key)
    else:
        client()


if __name__ == "__main__":
    main()
