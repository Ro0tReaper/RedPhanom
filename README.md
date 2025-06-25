# 🛡️ RedPhanom


[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)](https://www.python.org/downloads/)
![GitHub forks](https://img.shields.io/github/forks/Ro0tReaper/RedPhantom?style=flat-square)
![Project Age](https://img.shields.io/badge/project-new-blue?style=flat-square)
[![GitHub stars](https://img.shields.io/github/stars/Ro0tReaper/RedPhanom?style=flat-square)](https://github.com/Ro0tReaper/RedPhanom/stargazers)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen?style=flat-square)





**RedPhanom** is a modular red teaming and penetration testing toolkit written in Python, designed to streamline reconnaissance, exploitation, payload delivery, and obfuscation tasks. Built with extensibility and stealth in mind, RedPhanom equips offensive security professionals with a powerful command-line Swiss army knife for internal assessments, CTFs, and adversary simulations.

---

## ⚙️ Features

### 🔍 Reconnaissance
- Network scanning (ping sweep)
- Port scanning with multithreading
- Service banner enumeration
- Subdomain brute-forcing with live/dead checking

### 💥 Exploitation
- Reverse shell generator (bash, Python, PHP, Netcat, PowerShell)
- Real-world CVE modules (Apache Struts, Apache HTTPD, etc.)
- Web exploit payload crafting (command injection, RCE)
- Simulated or live attacks

### 📦 Payload Delivery
- HTTP server for payload hosting
- Auto-generated droppers (Bash, PowerShell, Python)
- Built-in TCP listener for reverse shells

### 🧠 Post-Exploitation
- User, hostname, and privilege discovery
- Enumeration of `.ssh`, cronjobs, and sudo privileges
- Sensitive file discovery

### 🎭 Obfuscation
- Base64, ROT13, XOR, and string reversing
- AES-128 encryption/decryption
- RSA keypair generation, encryption/decryption
- Script encoding for payload evasion

---

## 🧱 Structure

```bash
RedPhanom/
├── core/ # Core logic (menu, dispatcher)
├── modules/ # Recon, exploit, post-ex, etc.
│ ├── recon/
│ ├── exploit/
│ ├── post/
│ └── web/
├── data/ # Wordlists, payloads
│ └── wordlists/
├── main.py # Entry point
├── config.py # Config file
├── requirements.txt # Python dependencies
└── README.md
```
---

## 🚀 Getting Started

### ⚡ Prerequisites

- Python 3.8+
- Recommended: Linux or WSL (for full feature support)

### 📦 Install Dependencies

```bash
pip install -r requirements.txt
```
---
## Basic usage ▶️

```bash
git clone https://github.com/yourusername/RedPhanom
cd RedPhanom
pip install -r requirements.txt
python3 main.py
```

follow the menu to achieve your goal

```bash

[+] RedPhanom - The Modular Red Teaming Toolkit

[1] Reconnaissance
[2] Exploitation & Reverse shells
[3] Payload Generator
[4] Post-Exploitation
[5] Web Attacks
[6] Obfuscation
[q] Quit
```
---
## 📎 Example: Subdomain Enumeration

```bash
Select: [1] Reconnaissance -> [4] Enumerate subdomains

[*] Enumerating subdomains for google.com...

[+] mail.google.com           -> 142.250.65.69     [ALIVE]
[+] dev.google.com            -> 0.0.0.0           [DEAD]
```

---
## ⚠️ Legal Disclaimer ⚠️
> This toolkit is for educational and authorized testing purposes only. Misuse of this tool for illegal purposes is strictly forbidden. The developer of this framework is not responsible for any misuse or damage caused.

---
## 🤝 Contributions Welcome
Feel free to submit PRs with new modules, bug fixes, or enhancements!

### Future additions
 - *Advanced web attack modules* (SSRF, XSS, SQLi fuzzers)

 - *Lateral movement* and *pivoting* tools

 - *Automated reporting* and *session logging*

 - Agent-based *post-exploitation* framework

---

## 👨‍💻 Author
>RedPhanom was built by Mohamed Yossery (@Ro0tReaper) a junior offensive security enginner