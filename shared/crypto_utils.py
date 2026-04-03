"""
crypto_utils.py — Tiện ích mã hóa dùng chung cho client và server.
Sử dụng RSA-OAEP và AES-256-CBC thực sự từ thư viện `cryptography`.
"""

import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ─────────────────────────────────────────────
#  RSA
# ─────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    """Sinh cặp khóa RSA (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """Chuyển public key sang định dạng PEM (bytes)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    """Khôi phục public key từ PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """Mã hóa dữ liệu bằng RSA-OAEP (dùng để bọc AES key)."""
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Giải mã dữ liệu bằng RSA private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


# ─────────────────────────────────────────────
#  AES
# ─────────────────────────────────────────────

def generate_aes_key(key_size: int = 32) -> bytes:
    """Sinh AES key ngẫu nhiên (32 bytes = AES-256)."""
    return os.urandom(key_size)


def aes_encrypt(aes_key: bytes, plaintext: str) -> dict:
    """
    Mã hóa chuỗi bằng AES-256-CBC.
    Trả về dict gồm iv và ciphertext (đều là base64 string).
    """
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def aes_decrypt(aes_key: bytes, iv_b64: str, ciphertext_b64: str) -> str:
    """Giải mã AES-256-CBC, trả về plaintext string."""
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_to_bytes(data: str) -> bytes:
    return base64.b64decode(data)


def pretty_hex(data: bytes, width: int = 32) -> str:
    """In bytes dạng hex dễ đọc."""
    h = data.hex()
    return " ".join(h[i:i+2] for i in range(0, min(len(h), width*2), 2)) + ("..." if len(h) > width*2 else "")