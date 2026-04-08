"""
client.py — Client chat với mã hóa AES + RSA + hỗ trợ bật/tắt MITM.

bthg:
  python client.py alice
  python client.py bob

bật MITM:
  python client.py alice mitm
  python client.py bob mitm
"""

import socket
import threading
import json
import sys
import os
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    rsa_encrypt, rsa_decrypt,
    generate_aes_key, aes_encrypt, aes_decrypt,
    bytes_to_b64, b64_to_bytes, pretty_hex,
)

HOST = "127.0.0.1"

# ===== MITM TOGGLE =====
USE_ATTACKER = False

# parse CLI
if len(sys.argv) >= 3 and sys.argv[2].lower() == "mitm":
    USE_ATTACKER = True

# chọn PORT
if USE_ATTACKER:
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "alice":
        PORT = 5555   # attacker
    else:
        PORT = 65432  # server
else:
    PORT = 65432

# ANSI colors
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
MAGENTA= "\033[95m"


class ChatClient:
    def __init__(self, name: str):
        self.name = name
        self.color = CYAN if name == "alice" else GREEN

        print(f"\n{self.color}{BOLD}╔══════════════════════════════════════╗")
        print(f"║   AES + RSA Chat — {name.upper():<18}║")
        print(f"╚══════════════════════════════════════╝{RESET}\n")

        # Mode info
        if USE_ATTACKER:
            self._log("SYS", "⚠️ MITM MODE: Alice đi qua attacker")
        else:
            self._log("SYS", "🛡️ SECURE MODE: Kết nối trực tiếp server")

        # RSA
        self._log("RSA", "Đang sinh cặp khóa RSA-2048 ...")
        self.private_key, self.public_key = generate_rsa_keypair(2048)
        pub_pem = serialize_public_key(self.public_key)

        self._log("RSA", f"✓ Sinh xong cặp khóa RSA-2048")
        self._log("RSA", f"  Public key:\n{GRAY}{pub_pem.decode()[:200].strip()}{RESET}")
        self._log("RSA", f"  Private key (GIỮ BÍ MẬT)")

        self.pub_key_pem = pub_pem.decode()
        self.peer_pub_key = None
        self.aes_key: bytes = None

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _log(self, tag: str, msg: str):
        tags = {"RSA": YELLOW, "AES": GREEN, "SYS": CYAN, "ERR": RED}
        c = tags.get(tag, "")
        print(f"{c}[{tag}]{RESET} {msg}")

    def _send(self, data: dict):
        raw = json.dumps(data).encode("utf-8")
        self.conn.sendall(len(raw).to_bytes(4, "big") + raw)

    def _recv(self) -> dict:
        raw_len = b""
        while len(raw_len) < 4:
            chunk = self.conn.recv(4 - len(raw_len))
            if not chunk:
                raise ConnectionError
            raw_len += chunk

        length = int.from_bytes(raw_len, "big")

        raw = b""
        while len(raw) < length:
            raw += self.conn.recv(4096)

        return json.loads(raw.decode())

    def connect(self):
        self._log("SYS", f"Kết nối tới {HOST}:{PORT} ...")
        self.conn.connect((HOST, PORT))

        self._send({
            "type": "hello",
            "name": self.name,
            "pub_key_pem": self.pub_key_pem,
        })

        ack = self._recv()
        self._log("SYS", f"Server: {ack['msg']}")

    def _do_handshake_as_alice(self):
        self._log("SYS", "=== HANDSHAKE ALICE ===")

        self.aes_key = generate_aes_key(32)
        self._log("AES", f"AES key: {pretty_hex(self.aes_key)}")

        encrypted = rsa_encrypt(self.peer_pub_key, self.aes_key)

        self._send({
            "type": "aes_key_exchange",
            "encrypted_aes_key": bytes_to_b64(encrypted),
        })

        self._log("SYS", "✓ Đã gửi AES key")

    def _do_handshake_as_bob(self, encrypted_key_b64):
        self._log("SYS", "=== HANDSHAKE BOB ===")

        encrypted = b64_to_bytes(encrypted_key_b64)
        self.aes_key = rsa_decrypt(self.private_key, encrypted)

        self._log("AES", f"AES key: {pretty_hex(self.aes_key)}")

    def _recv_loop(self):
        try:
            while True:
                msg = self._recv()

                if msg["type"] == "peer_pubkey":
                    self.peer_pub_key = deserialize_public_key(msg["pub_key_pem"].encode())

                    if self.name == "alice":
                        self._do_handshake_as_alice()

                elif msg["type"] == "aes_key_exchange":
                    if self.name == "bob":
                        self._do_handshake_as_bob(msg["encrypted_aes_key"])

                elif msg["type"] == "chat":
                    if not self.aes_key:
                        continue

                    plaintext = aes_decrypt(
                        self.aes_key,
                        msg["iv"],
                        msg["ciphertext"]
                    )

                    print(f"\n{msg['from'].upper()}: {plaintext}")
                    print(f"{self.name.upper()}> ", end="", flush=True)

        except:
            self._log("SYS", "Mất kết nối")

    def chat_loop(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()

        while True:
            try:
                text = input(f"{self.name.upper()}> ")

                if not self.aes_key:
                    print("Chưa handshake xong")
                    continue

                enc = aes_encrypt(self.aes_key, text)

                self._send({
                    "type": "chat",
                    "iv": enc["iv"],
                    "ciphertext": enc["ciphertext"],
                })

            except:
                break


def main():
    if len(sys.argv) < 2:
        print("Dùng: python client.py alice|bob [mitm]")
        return

    name = sys.argv[1].lower()
    client = ChatClient(name)
    client.connect()
    client.chat_loop()


if __name__ == "__main__":
    main()