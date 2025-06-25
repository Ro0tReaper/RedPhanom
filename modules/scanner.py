import socket
import ipaddress
import threading
import platform
import subprocess
from queue import Queue

#import dns.resolver
import socket


print_lock = threading.Lock()

# Ping a single host to check if it's alive
def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-W", "1", str(ip)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL)
    return result.returncode == 0

# Scan a network (ping sweep)
def scan_network(network_cidr):
    print(f"[*] Scanning network {network_cidr}...\n")
    alive_hosts = []

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print("[!] Invalid CIDR format.")
        return []

    def worker(ip):
        if ping_host(ip):
            with print_lock:
                print(f"[+] Host {ip} is alive")
                alive_hosts.append(str(ip))

    threads = []
    for ip in network.hosts():
        t = threading.Thread(target=worker, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[*] Found {len(alive_hosts)} alive host(s).")
    return alive_hosts


# Scan a single host for open ports
def scan_ports(ip, ports=None):
    if ports is None:
        ports = list(range(1, 1025))  # Default to well-known ports

    print(f"[*] Scanning {ip} for open ports...\n")

    open_ports = []

    def worker(port):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                with print_lock:
                    print(f"[+] Port {port} is open")
                    open_ports.append(port)
            s.close()
        except:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")
    return open_ports


# Basic service enumeration (banner grabbing)
def enumerate_services(ip, ports):
    print(f"[*] Enumerating services on {ip}...\n")

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            print(f"[+] Port {port}: {banner}")
            s.close()
        except:
            print(f"[-] Port {port}: No response / Not bannered")
## SUBDOMAIN ENUM
import socket
import requests
import urllib3
from threading import Thread, Lock
from queue import Queue

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print_lock = Lock()

def enumerate_subdomains(domain, wordlist_path="data/wordlists/subdomains.txt", threads=50, save_file=None):
    print(f"[*] Enumerating subdomains for {domain} using {threads} threads...\n")

    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found at {wordlist_path}")
        return

    q = Queue()
    found = []

    for sub in subdomains:
        q.put(sub)

    def worker():
        while not q.empty():
            sub = q.get()
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
            except socket.gaierror:
                q.task_done()
                continue

            alive = False
            for scheme in ["https", "http"]:
                try:
                    res = requests.get(f"{scheme}://{subdomain}", timeout=3, allow_redirects=True, verify=False)
                    if res.status_code < 500:
                        alive = True
                        break
                except requests.RequestException:
                    continue

            status = "ALIVE" if alive else "DEAD"
            with print_lock:
                print(f"[+] {subdomain:<30} -> {ip:<15} [{status}]")
                found.append((subdomain, ip, alive))
                if alive and save_file:
                    with open(save_file, 'a') as f:
                        f.write(f"{subdomain} -> {ip}\n")
            q.task_done()

    thread_list = []
    for _ in range(min(threads, len(subdomains))):
        t = Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    q.join()
    print(f"\n[*] Enumeration complete. {len(found)} subdomain(s) resolved.")