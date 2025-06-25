from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

import banner
from modules import postex, obfuscation, payloads, exploit, scanner, delivery

console = Console()

def main_menu():
    banner.print_banner()
    while True:
        table = Table(title="Main Menu", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Description", style="bold white")
        table.add_row("[1]", "Reconnaissance")
        table.add_row("[2]", "Exploitation")
        table.add_row("[3]", "Payload Generator")
        table.add_row("[4]", "Post-Exploitation")
        table.add_row("[5]", "Obfuscation & Cryptographic operations")
        table.add_row("[6]", "Delivery and Listeners")
        table.add_row("[q]", "Quit")

        console.print(table)

        choice = Prompt.ask("[bold yellow]Select Module[/]", choices=['1','2','3','4','5','6','q'])

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
            console.print("[bold red]Quitting... Bye![/]")
            break

def recon_menu():
    while True:
        table = Table(title="Reconnaissance Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Scan a network (ping sweep)")
        table.add_row("[2]", "Scan a device for open ports")
        table.add_row("[3]", "Enumerate services on a device")
        table.add_row("[4]", "Enumerate subdomains")
        table.add_row("[b]", "Back")

        console.print(table)
        choice = Prompt.ask("[bold yellow]Select Option[/]", choices=['1','2','3','4','b'])

        if choice == '1':
            cidr = Prompt.ask("Enter network (CIDR, e.g. 192.168.1.0/24)")
            scanner.scan_network(cidr)

        elif choice == '2':
            ip = Prompt.ask("Enter IP address to scan")
            port_range = Prompt.ask("Port range (default 1-1024, e.g. 20-80)", default="")
            if port_range and '-' in port_range:
                try:
                    start, end = map(int, port_range.split('-'))
                    ports = list(range(start, end + 1))
                except Exception:
                    console.print("[red][!] Invalid port range, using default 1-1024[/red]")
                    ports = list(range(1, 1025))
            else:
                ports = list(range(1, 1025))
            scanner.scan_ports(ip, ports)

        elif choice == '3':
            ip = Prompt.ask("Enter target IP")
            port_list = Prompt.ask("Enter comma-separated ports (e.g. 22,80,443)")
            try:
                ports = [int(p.strip()) for p in port_list.split(',')]
            except Exception:
                console.print("[red][!] Invalid port list[/red]")
                continue
            scanner.enumerate_services(ip, ports)

        elif choice == '4':
            domain = Prompt.ask("Enter domain (e.g. example.com)")
            save = Prompt.ask("Save alive subdomains to file? (y/n)", choices=['y','n'])
            save_file = None
            if save == 'y':
                save_file = Prompt.ask("Enter file name to save (e.g. alive.txt)")
                with open(save_file, 'w') as f:
                    f.write(f"# Alive subdomains for {domain}\n")
            scanner.enumerate_subdomains(domain, save_file=save_file)

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

def exploit_menu():
    while True:
        table = Table(title="Exploitation Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Test SQL Injection (boolean)")
        table.add_row("[2]", "Test Local File Inclusion (LFI)")
        table.add_row("[3]", "Test Command Injection")
        table.add_row("[4]", "Test Reflected XSS")
        table.add_row("[5]", "Test SMB Null Session")
        table.add_row("[6]", "Test SNMP Public Community")
        table.add_row("[7]", "Test FTP Anonymous Login")
        table.add_row("[8]", "Ping Host (ICMP)")
        table.add_row("[b]", "Back")

        console.print(table)
        choice = Prompt.ask("[bold yellow]Select option[/]", choices=['1','2','3','4','5','6','7','8','b'])

        if choice == '1':
            url = Prompt.ask("Target URL (e.g. http://example.com/page)")
            param = Prompt.ask("Vulnerable parameter name")
            success, msg = exploit.test_sql_injection(url, param)
            console.print(msg)

        elif choice == '2':
            url = Prompt.ask("Target URL (e.g. http://example.com/page)")
            param = Prompt.ask("Vulnerable parameter name")
            success, msg, content = exploit.test_lfi(url, param)
            console.print(msg)
            if success:
                console.print(content)

        elif choice == '3':
            url = Prompt.ask("Target URL (e.g. http://example.com/page)")
            param = Prompt.ask("Vulnerable parameter name")
            cmd = Prompt.ask("Command to execute (default 'id')", default="id")
            success, msg = exploit.test_cmd_injection(url, param, cmd)
            console.print(msg)

        elif choice == '4':
            url = Prompt.ask("Target URL (e.g. http://example.com/page)")
            param = Prompt.ask("Vulnerable parameter name")
            success, msg = exploit.test_xss(url, param)
            console.print(msg)

        elif choice == '5':
            ip = Prompt.ask("Target IP")
            success, msg = exploit.test_smb_null_session(ip)
            console.print(msg)

        elif choice == '6':
            ip = Prompt.ask("Target IP")
            success, msg = exploit.test_snmp_public_community(ip)
            console.print(msg)

        elif choice == '7':
            ip = Prompt.ask("Target IP")
            success, msg = exploit.test_ftp_anonymous_login(ip)
            console.print(msg)

        elif choice == '8':
            ip = Prompt.ask("Target IP")
            success, msg = exploit.test_icmp_ping(ip)
            console.print(msg)

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

def payload_menu():
    while True:
        table = Table(title="Payload Generator Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Generate reverse shell")
        table.add_row("[2]", "Base64 encode payload")
        table.add_row("[3]", "Generate download & execute payload")
        table.add_row("[b]", "Back")

        console.print(table)
        choice = Prompt.ask("[bold yellow]Select option[/]", choices=['1','2','3','b'])

        if choice == '1':
            ip = Prompt.ask("Listener IP")
            port = Prompt.ask("Listener port")
            shell = Prompt.ask("Shell type (bash/python/php/nc/powershell)")
            payload = payloads.generate_reverse_shell(ip, port, shell)
            console.print("\n[bold green][+] Reverse Shell Payload:[/bold green]\n")
            console.print(payload + "\n")

        elif choice == '2':
            payload = Prompt.ask("Enter the payload to encode")
            encoded = payloads.base64_encode_payload(payload)
            console.print("\n[bold green][+] Base64 Encoded Payload:[/bold green]\n")
            console.print(encoded + "\n")

        elif choice == '3':
            url = Prompt.ask("URL of payload to download")
            filename = Prompt.ask("Filename to save as (default: payload.sh)", default="payload.sh")
            payload = payloads.generate_download_execute(url, filename)
            console.print("\n[bold green][+] Download & Execute Payload:[/bold green]\n")
            console.print(payload + "\n")

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

def postex_menu():
    while True:
        table = Table(title="Post-Exploitation Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Get basic system info")
        table.add_row("[2]", "List users")
        table.add_row("[3]", "List environment variables")
        table.add_row("[4]", "Find sensitive password/hash files")
        table.add_row("[5]", "List running processes")
        table.add_row("[6]", "Check sudo permissions")
        table.add_row("[7]", "Check crontab / scheduled tasks")
        table.add_row("[b]", "Back")

        console.print(table)
        console.print("[red][Note] move RedPhantom to the target machine in order for it to gather information[/red]\n")
        choice = Prompt.ask("[bold yellow]Select option[/]", choices=['1','2','3','4','5','6','7','b'])

        if choice == '1':
            info = postex.get_system_info()
            for k, v in info.items():
                console.print(f"[cyan]{k}[/cyan]: {v}")

        elif choice == '2':
            output = postex.list_users()
            console.print(output)

        elif choice == '3':
            env_vars = postex.list_env_vars()
            for key, val in env_vars.items():
                console.print(f"{key}={val}")

        elif choice == '4':
            files = postex.find_password_files()
            for f in files:
                console.print(f)

        elif choice == '5':
            output = postex.list_processes()
            console.print(output)

        elif choice == '6':
            output = postex.check_sudo_permissions()
            console.print(output)

        elif choice == '7':
            output = postex.check_crontab()
            console.print(output)

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

def obfuscation_menu():
    while True:
        table = Table(title="Obfuscation Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Base64 Encode")
        table.add_row("[2]", "Base64 Decode")
        table.add_row("[3]", "ROT13 Encode/Decode")
        table.add_row("[4]", "Reverse String")
        table.add_row("[5]", "XOR Encrypt")
        table.add_row("[6]", "XOR Decrypt")
        table.add_row("[7]", "AES-128 Encrypt")
        table.add_row("[8]", "AES-128 Decrypt")
        table.add_row("[9]", "Generate RSA Keypair")
        table.add_row("[10]", "RSA Encrypt")
        table.add_row("[11]", "RSA Decrypt")
        table.add_row("[b]", "Back")

        console.print(table)
        choice = Prompt.ask("[bold yellow]Select option[/]", choices=[str(i) for i in range(1,12)]+['b'])

        if choice == '1':
            data = Prompt.ask("Enter data to Base64 encode")
            encoded = obfuscation.base64_encode(data)
            console.print(f"\n[bold green][+] Base64 Encoded:[/bold green]\n{encoded}\n")

        elif choice == '2':
            data = Prompt.ask("Enter Base64 string to decode")
            decoded = obfuscation.base64_decode(data)
            console.print(f"\n[bold green][+] Decoded:[/bold green]\n{decoded}\n")

        elif choice == '3':
            data = Prompt.ask("Enter text to encode/decode with ROT13")
            result = obfuscation.rot13(data)
            console.print(f"\n[bold green][+] ROT13 Result:[/bold green]\n{result}\n")

        elif choice == '4':
            data = Prompt.ask("Enter string to reverse")
            reversed_data = obfuscation.reverse_string(data)
            console.print(f"\n[bold green][+] Reversed:[/bold green]\n{reversed_data}\n")

        elif choice == '5':
            data = Prompt.ask("Enter data to XOR encrypt")
            key = Prompt.ask("Enter XOR key")
            result = obfuscation.xor_encrypt(data, key)
            console.print(f"\n[bold green][+] XOR Encrypted (base64):[/bold green]\n{result}\n")

        elif choice == '6':
            data = Prompt.ask("Enter base64-encoded XOR data to decrypt")
            key = Prompt.ask("Enter XOR key")
            result = obfuscation.xor_decrypt(data, key)
            console.print(f"\n[bold green][+] Decrypted:[/bold green]\n{result}\n")

        elif choice == '7':
            data = Prompt.ask("Enter data to AES-128 encrypt")
            key = Prompt.ask("Enter 16-char key (or shorter)")
            encrypted = obfuscation.aes_encrypt(data, key)
            console.print(f"\n[bold green][+] AES Encrypted (base64):[/bold green]\n{encrypted}\n")

        elif choice == '8':
            data = Prompt.ask("Enter AES-encrypted base64 string")
            key = Prompt.ask("Enter AES decryption key")
            decrypted = obfuscation.aes_decrypt(data, key)
            console.print(f"\n[bold green][+] Decrypted:[/bold green]\n{decrypted}\n")

        elif choice == '9':
            priv, pub = obfuscation.generate_rsa_keypair()
            console.print(f"\n[bold green][+] Private Key:[/bold green]\n{priv}")
            console.print(f"[bold green][+] Public Key:[/bold green]\n{pub}")

        elif choice == '10':
            pub_key = Prompt.ask("Paste RSA Public Key")
            msg = Prompt.ask("Enter message to encrypt")
            encrypted = obfuscation.rsa_encrypt(msg, pub_key)
            console.print(f"\n[bold green][+] Encrypted (base64):[/bold green]\n{encrypted}\n")

        elif choice == '11':
            priv_key = Prompt.ask("Paste RSA Private Key")
            msg = Prompt.ask("Enter base64-encoded ciphertext")
            decrypted = obfuscation.rsa_decrypt(msg, priv_key)
            console.print(f"\n[bold green][+] Decrypted:[/bold green]\n{decrypted}\n")

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

def delivery_menu():
    while True:
        table = Table(title="Payload Delivery Module", title_style="bold cyan")
        table.add_column("Option", style="bold green", justify="center")
        table.add_column("Action", style="bold white")
        table.add_row("[1]", "Start HTTP Server for Payloads")
        table.add_row("[2]", "Generate Bash Dropper")
        table.add_row("[3]", "Generate PowerShell Dropper")
        table.add_row("[4]", "Generate Python Dropper")
        table.add_row("[5]", "Start TCP Listener (reverse shell catcher)")
        table.add_row("[b]", "Back")

        console.print(table)
        choice = Prompt.ask("[bold yellow]Select option[/]", choices=['1','2','3','4','5','b'])

        if choice == '1':
            port = Prompt.ask("Port to host HTTP server on (default 8000)", default="8000")
            directory = Prompt.ask("Directory to serve files from (default current)", default=".")
            delivery.start_http_server(int(port), directory)

        elif choice == '2':
            url = Prompt.ask("Enter payload URL (e.g. http://IP/payload.sh)")
            console.print("\n[bold green][+] Bash Dropper:[/bold green]\n")
            console.print(delivery.generate_bash_dropper(url) + "\n")

        elif choice == '3':
            url = Prompt.ask("Enter payload URL (e.g. http://IP/payload.ps1)")
            console.print("\n[bold green][+] PowerShell Dropper:[/bold green]\n")
            console.print(delivery.generate_powershell_dropper(url) + "\n")

        elif choice == '4':
            url = Prompt.ask("Enter payload URL (e.g. http://IP/payload.py)")
            console.print("\n[bold green][+] Python Dropper:[/bold green]\n")
            console.print(delivery.generate_python_dropper(url) + "\n")

        elif choice == '5':
            ip = Prompt.ask("Listener IP (default 0.0.0.0)", default="0.0.0.0")
            port = Prompt.ask("Listener port (default 4444)", default="4444")
            delivery.start_tcp_listener(ip, int(port))

        elif choice == 'b':
            break

        else:
            console.print("[red][!] Invalid option.[/red]\n")

if __name__ == "__main__":
    main_menu()
