"""
crypto_utils.py — Tiện ích mã hóa dùng chung cho client và server.
Sử dụng RSA-OAEP, AES-256-CBC và Digital Signature (RSA-PSS).
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
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─────────────────────────────────────────────
#  AES
# ─────────────────────────────────────────────

def generate_aes_key(key_size: int = 32) -> bytes:
    return os.urandom(key_size)


def aes_encrypt(aes_key: bytes, plaintext: str) -> dict:
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def aes_decrypt(aes_key: bytes, iv_b64: str, ciphertext_b64: str) -> str:
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode()


# ─────────────────────────────────────────────
#  DIGITAL SIGNATURE
# ─────────────────────────────────────────────

def rsa_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_to_bytes(data: str) -> bytes:
    return base64.b64decode(data)


def pretty_hex(data: bytes, width: int = 32) -> str:
    h = data.hex()
    return " ".join(h[i:i+2] for i in range(0, min(len(h), width*2), 2)) + ("..." if len(h) > width*2 else "")