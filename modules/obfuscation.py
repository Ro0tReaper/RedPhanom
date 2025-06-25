import base64

# --- Simple Encodings ---
def base64_encode(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def base64_decode(data: str) -> str:
    try:
        return base64.b64decode(data.encode()).decode()
    except Exception as e:
        return f"[!] Decode failed: {e}"

def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

def reverse_string(s: str) -> str:
    return s[::-1]

def xor_encrypt(data: str, key: str) -> str:
    xored = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return base64.b64encode(xored.encode()).decode()

def xor_decrypt(encoded: str, key: str) -> str:
    try:
        xored = base64.b64decode(encoded.encode()).decode()
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(xored))
    except Exception as e:
        return f"[!] XOR decryption failed: {e}"

# --- AES-128 Encryption/Decryption ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt(data: str, key: str) -> str:
    key_bytes = key.encode().ljust(16, b'\x00')[:16]  # AES-128
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ct).decode()

def aes_decrypt(encoded: str, key: str) -> str:
    try:
        key_bytes = key.encode().ljust(16, b'\x00')[:16]
        raw = base64.b64decode(encoded.encode())
        iv, ct = raw[:16], raw[16:]

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data.decode()
    except Exception as e:
        return f"[!] AES decryption failed: {e}"

# --- RSA Encryption/Decryption ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem.decode(), pub_pem.decode()

def rsa_encrypt(data: str, public_key_pem: str) -> str:
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        ct = pub_key.encrypt(
            data.encode(),
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[!] RSA encryption failed: {e}"

def rsa_decrypt(encoded: str, private_key_pem: str) -> str:
    try:
        priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
        ct = base64.b64decode(encoded.encode())
        pt = priv_key.decrypt(
            ct,
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return pt.decode()
    except Exception as e:
        return f"[!] RSA decryption failed: {e}"
