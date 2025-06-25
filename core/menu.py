from modules import postex, obfuscation, payloads, exploit, scanner, delivery
import banner
def main_menu():
    banner.print_banner()
    while True:
        print("""
[+] RedPhantom - The Modular Red Teaming Toolkit

[1] Reconnaissance
[2] Exploitation
[3] Payload Generator
[4] Post-Exploitation
[5] Obfuscation & Cryptographic operations
[6] Delivery and Listeners
[q] Quit
""")
        choice = input("Select Module: ").strip()

        if choice == '1':
            recon_menu()
        elif choice == '2':
            exploit_menu()
        elif choice == '3':
            payload_menu()
        elif choice == '4':
            postex_menu()
        elif choice == '5':
            obfuscation_menu()
        elif choice == '6':
            delivery_menu()
        elif choice == 'q':
            print("Quitting... Bye!")
            break

        else:
            print("[!] Invalid option.\n")


def recon_menu():
    while True:
        print("""
--- Reconnaissance Module ---

[1] Scan a network (ping sweep)
[2] Scan a device for open ports
[3] Enumerate services on a device
[4] Enumerate subdomains
[b] Back
""")
        choice = input("Select Option: ").strip()

        if choice == '1':
            cidr = input("Enter network (CIDR, e.g. 192.168.1.0/24): ").strip()
            scanner.scan_network(cidr)

        elif choice == '2':
            ip = input("Enter IP address to scan: ").strip()
            port_range = input("Port range (default 1-1024, e.g. 20-80): ").strip()
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = list(range(1, 1025))
            scanner.scan_ports(ip, ports)

        elif choice == '3':
            ip = input("Enter target IP: ").strip()
            port_list = input("Enter comma-separated ports (e.g. 22,80,443): ").strip()
            ports = [int(p.strip()) for p in port_list.split(',')]
            scanner.enumerate_services(ip, ports)

        elif choice == '4':
            domain = input("Enter domain (e.g. example.com): ").strip()
            save = input("Save alive subdomains to file? (y/n): ").strip().lower()
            save_file = None
            if save == 'y':
                save_file = input("Enter file name to save (e.g. alive.txt): ").strip()
                with open(save_file, 'w') as f:
                    f.write(f"# Alive subdomains for {domain}\n")

            scanner.enumerate_subdomains(domain, save_file=save_file)

        elif choice == 'b':
            break

        else:
            print("[!] Invalid option.\n")




def exploit_menu():
    while True:
        print("""
--- Exploitation Module ---

[1] Test SQL Injection (boolean)
[2] Test Local File Inclusion (LFI)
[3] Test Command Injection
[4] Test Reflected XSS
[5] Test SMB Null Session
[6] Test SNMP Public Community
[7] Test FTP Anonymous Login
[8] Ping Host (ICMP)
[b] Back
""")
        choice = input("Select option: ").strip()

        if choice == '1':
            url = input("Target URL (e.g. http://example.com/page): ").strip()
            param = input("Vulnerable parameter name: ").strip()
            success, msg = exploit.test_sql_injection(url, param)
            print(msg)

        elif choice == '2':
            url = input("Target URL (e.g. http://example.com/page): ").strip()
            param = input("Vulnerable parameter name: ").strip()
            success, msg, content = exploit.test_lfi(url, param)
            print(msg)
            if success:
                print(content)

        elif choice == '3':
            url = input("Target URL (e.g. http://example.com/page): ").strip()
            param = input("Vulnerable parameter name: ").strip()
            cmd = input("Command to execute (default 'id'): ").strip() or "id"
            success, msg = exploit.test_cmd_injection(url, param, cmd)
            print(msg)

        elif choice == '4':
            url = input("Target URL (e.g. http://example.com/page): ").strip()
            param = input("Vulnerable parameter name: ").strip()
            success, msg = exploit.test_xss(url, param)
            print(msg)

        elif choice == '5':
            ip = input("Target IP: ").strip()
            success, msg = exploit.test_smb_null_session(ip)
            print(msg)

        elif choice == '6':
            ip = input("Target IP: ").strip()
            success, msg = exploit.test_snmp_public_community(ip)
            print(msg)

        elif choice == '7':
            ip = input("Target IP: ").strip()
            success, msg = exploit.test_ftp_anonymous_login(ip)
            print(msg)

        elif choice == '8':
            ip = input("Target IP: ").strip()
            success, msg = exploit.test_icmp_ping(ip)
            print(msg)

        elif choice == 'b':
            break

        else:
            print("[!] Invalid option.")

def payload_menu():
    while True:
        print("""
--- Payload Generator Module ---

[1] Generate reverse shell
[2] Base64 encode payload
[3] Generate download & execute payload
[b] Back
""")
        choice = input("Select option: ").strip()

        if choice == '1':
            ip = input("Listener IP: ").strip()
            port = input("Listener port: ").strip()
            shell = input("Shell type (bash/python/php/nc/powershell): ").strip()
            payload = payloads.generate_reverse_shell(ip, port, shell)
            print("\n[+] Reverse Shell Payload:\n")
            print(payload + "\n")

        elif choice == '2':
            payload = input("Enter the payload to encode: ").strip()
            encoded = payloads.base64_encode_payload(payload)
            print("\n[+] Base64 Encoded Payload:\n")
            print(encoded + "\n")

        elif choice == '3':
            url = input("URL of payload to download: ").strip()
            filename = input("Filename to save as (default: payload.sh): ").strip()
            if not filename:
                filename = "payload.sh"
            payload = payloads.generate_download_execute(url, filename)
            print("\n[+] Download & Execute Payload:\n")
            print(payload + "\n")

        elif choice == 'b':
            break
        else:
            print("[!] Invalid option.")

def postex_menu():
    while True:
        print("""
--- Post-Exploitation Module ---
              
*NOTE: for this section move RedPhantom to the target machine for it to gather the required info*
              
[1] Get basic system info
[2] List users
[3] List environment variables
[4] Find sensitive password/hash files
[5] List running processes
[6] Check sudo permissions
[7] Check crontab / scheduled tasks
[b] Back
""")
        choice = input("Select option: ").strip()

        if choice == '1':
            info = postex.get_system_info()
            for k, v in info.items():
                print(f"{k}: {v}")

        elif choice == '2':
            output = postex.list_users()
            print(output)

        elif choice == '3':
            env_vars = postex.list_env_vars()
            for key, val in env_vars.items():
                print(f"{key}={val}")

        elif choice == '4':
            files = postex.find_password_files()
            for f in files:
                print(f)

        elif choice == '5':
            output = postex.list_processes()
            print(output)

        elif choice == '6':
            output = postex.check_sudo_permissions()
            print(output)

        elif choice == '7':
            output = postex.check_crontab()
            print(output)

        elif choice == 'b':
            break

        else:
            print("[!] Invalid option.")

def obfuscation_menu():
    while True:
        print("""
--- Obfuscation Module ---

[1] Base64 Encode
[2] Base64 Decode
[3] ROT13 Encode/Decode
[4] Reverse String
[5] XOR Encrypt
[6] XOR Decrypt
[7] AES-128 Encrypt
[8] AES-128 Decrypt
[9] Generate RSA Keypair
[10] RSA Encrypt
[11] RSA Decrypt
[b] Back
""")
        choice = input("Select option: ").strip()

        if choice == '1':
            data = input("Enter data to Base64 encode: ")
            encoded = obfuscation.base64_encode(data)
            print(f"\n[+] Base64 Encoded:\n{encoded}\n")

        elif choice == '2':
            data = input("Enter Base64 string to decode: ")
            decoded = obfuscation.base64_decode(data)
            print(f"\n[+] Decoded:\n{decoded}\n")

        elif choice == '3':
            data = input("Enter text to encode/decode with ROT13: ")
            result = obfuscation.rot13(data)
            print(f"\n[+] ROT13 Result:\n{result}\n")

        elif choice == '4':
            data = input("Enter string to reverse: ")
            reversed_data = obfuscation.reverse_string(data)
            print(f"\n[+] Reversed:\n{reversed_data}\n")

        elif choice == '5':
            data = input("Enter data to XOR encrypt: ")
            key = input("Enter XOR key: ")
            result = obfuscation.xor_encrypt(data, key)
            print(f"\n[+] XOR Encrypted (base64):\n{result}\n")

        elif choice == '6':
            data = input("Enter base64-encoded XOR data to decrypt: ")
            key = input("Enter XOR key: ")
            result = obfuscation.xor_decrypt(data, key)
            print(f"\n[+] Decrypted:\n{result}\n")
        elif choice == '7':
            data = input("Enter data to AES-128 encrypt: ")
            key = input("Enter 16-char key (or shorter): ")
            encrypted = obfuscation.aes_encrypt(data, key)
            print(f"\n[+] AES Encrypted (base64):\n{encrypted}\n")

        elif choice == '8':
            data = input("Enter AES-encrypted base64 string: ")
            key = input("Enter AES decryption key: ")
            decrypted = obfuscation.aes_decrypt(data, key)
            print(f"\n[+] Decrypted:\n{decrypted}\n")

        elif choice == '9':
            priv, pub = obfuscation.generate_rsa_keypair()
            print(f"\n[+] Private Key:\n{priv}")
            print(f"[+] Public Key:\n{pub}")

        elif choice == '10':
            pub_key = input("Paste RSA Public Key:\n")
            msg = input("Enter message to encrypt: ")
            encrypted = obfuscation.rsa_encrypt(msg, pub_key)
            print(f"\n[+] Encrypted (base64):\n{encrypted}\n")

        elif choice == '11':
            priv_key = input("Paste RSA Private Key:\n")
            msg = input("Enter base64-encoded ciphertext: ")
            decrypted = obfuscation.rsa_decrypt(msg, priv_key)
            print(f"\n[+] Decrypted:\n{decrypted}\n")

        elif choice == 'b':
            break

        else:
            print("[!] Invalid option.\n")



def delivery_menu():
    while True:
        print("""
--- Payload Delivery Module ---

[1] Start HTTP Server for Payloads
[2] Generate Bash Dropper
[3] Generate PowerShell Dropper
[4] Generate Python Dropper
[5] Start TCP Listener (reverse shell catcher)
[b] Back
""")
        choice = input("Select option: ").strip()

        if choice == '1':
            port = input("Port to host HTTP server on (default 8000): ").strip() or "8000"
            directory = input("Directory to serve files from (default current): ").strip() or "."
            delivery.start_http_server(int(port), directory)

        elif choice == '2':
            url = input("Enter payload URL (e.g. http://IP/payload.sh): ")
            print("\n[+] Bash Dropper:\n")
            print(delivery.generate_bash_dropper(url) + "\n")

        elif choice == '3':
            url = input("Enter payload URL (e.g. http://IP/payload.ps1): ")
            print("\n[+] PowerShell Dropper:\n")
            print(delivery.generate_powershell_dropper(url) + "\n")

        elif choice == '4':
            url = input("Enter payload URL (e.g. http://IP/payload.py): ")
            print("\n[+] Python Dropper:\n")
            print(delivery.generate_python_dropper(url) + "\n")

        elif choice == '5':
            ip = input("Listener IP (default 0.0.0.0): ").strip() or "0.0.0.0"
            port = input("Listener port (default 4444): ").strip() or "4444"
            delivery.start_tcp_listener(ip, int(port))

        elif choice == 'b':
            break

        else:
            print("[!] Invalid option.\n")
