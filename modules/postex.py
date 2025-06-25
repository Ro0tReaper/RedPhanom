import os
import subprocess
import platform

def get_system_info():
    """Basic system fingerprinting."""
    info = {
        "OS": platform.system(),
        "Release": platform.release(),
        "Architecture": platform.machine(),
        "Hostname": platform.node(),
        "User": os.getenv("USER") or os.getenv("USERNAME"),
    }
    return info

def list_users():
    """List users from /etc/passwd (Linux) or query via 'net user' (Windows)."""
    try:
        if platform.system().lower() == "windows":
            result = subprocess.check_output("net user", shell=True)
            return result.decode(errors="ignore")
        else:
            with open("/etc/passwd") as f:
                return f.read()
    except Exception as e:
        return f"[!] Error listing users: {e}"

def list_env_vars():
    """Print all environment variables."""
    return dict(os.environ)

def find_password_files():
    """Search for common sensitive files on Linux systems."""
    common_files = ["/etc/shadow", "/etc/passwd", "~/.bash_history", "~/.ssh/id_rsa"]
    results = []

    for file in common_files:
        path = os.path.expanduser(file)
        if os.path.exists(path):
            results.append(f"[+] Found: {path}")
        else:
            results.append(f"[-] Missing: {path}")
    return results

def list_processes():
    """List running processes."""
    try:
        if platform.system().lower() == "windows":
            result = subprocess.check_output("tasklist", shell=True)
        else:
            result = subprocess.check_output(["ps", "aux"])
        return result.decode(errors="ignore")
    except Exception as e:
        return f"[!] Error listing processes: {e}"

def check_sudo_permissions():
    """Check sudo privileges for the current user (Linux only)."""
    try:
        result = subprocess.check_output("sudo -l", shell=True, stderr=subprocess.STDOUT)
        return result.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"[!] Sudo check failed: {e.output.decode(errors='ignore')}"
    except Exception as e:
        return f"[!] Error running sudo check: {e}"

def check_crontab():
    """List user crontab and global cron jobs."""
    output = ""
    try:
        user_cron = subprocess.check_output("crontab -l", shell=True, stderr=subprocess.DEVNULL)
        output += "[+] User crontab:\n" + user_cron.decode(errors="ignore") + "\n"
    except subprocess.CalledProcessError:
        output += "[-] No user crontab found.\n"

    try:
        with open("/etc/crontab", "r") as f:
            output += "[+] /etc/crontab contents:\n" + f.read()
    except:
        output += "[-] /etc/crontab not readable or not found."

    return output
