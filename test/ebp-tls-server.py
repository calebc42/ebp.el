#!/usr/bin/env python3
"""Scripted TLS listener for the SPEC 5.4 `network-tls' wire tests.

Usage: ebp-tls-server.py PORT CERT KEY NACCEPT

Binds 127.0.0.1:PORT with a TLS 1.3+ context presenting CERT/KEY, prints
LISTENING once bound, and for each of NACCEPT connections prints
HANDSHAKE-OK <version> or HANDSHAKE-FAIL <reason>, then everything the
peer sent (as a Python bytes literal) as RECEIVED ... once the peer
closes or falls silent for two seconds.  It never answers, so a client
under test can only be observed, never driven, which is all the pinning
tests need: the frame Emacs sends -- or refuses to send -- before the
peer replies is the whole conformance question.
"""
import socket
import ssl
import sys

port, cert, key, n = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(cert, key)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print("LISTENING", flush=True)
for _ in range(n):
    conn, _addr = srv.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except Exception as exc:  # noqa: BLE001 - report every failure shape
        print("HANDSHAKE-FAIL", repr(exc), flush=True)
        conn.close()
        continue
    print("HANDSHAKE-OK", tls.version(), flush=True)
    tls.settimeout(2.0)
    data = b""
    try:
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:  # noqa: BLE001 - timeout or reset both end the read
        pass
    print("RECEIVED", repr(data), flush=True)
    try:
        tls.close()
    except Exception:  # noqa: BLE001
        pass
