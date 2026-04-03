"""
client.py — Client chat với mã hóa AES + RSA thực sự.

Cách dùng:
  python client.py alice
  python client.py bob    (chạy terminal khác)

Luồng hoạt động:
  1. Sinh cặp khóa RSA-2048 của chính mình.
  2. Gửi public key lên server.
  3. Nhận public key của peer từ server.
  4. Nếu là alice: sinh AES-256 key, mã hóa bằng RSA public của bob, gửi qua server.
     Nếu là bob: nhận gói RSA, giải mã bằng private key của mình → lấy AES key.
  5. Chat bình thường: mỗi tin nhắn được mã hóa AES-256-CBC trước khi gửi.
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

        # Bước 1: Sinh RSA key pair
        self._log("RSA", "Đang sinh cặp khóa RSA-2048 ...")
        self.private_key, self.public_key = generate_rsa_keypair(2048)
        pub_pem = serialize_public_key(self.public_key)
        self._log("RSA", f"✓ Sinh xong cặp khóa RSA-2048")
        self._log("RSA", f"  Public key  (gửi lên server):\n{GRAY}{pub_pem.decode()[:200].strip()}{RESET}")
        self._log("RSA", f"  Private key (GIỮ BÍ MẬT, không bao giờ rời máy này)")

        self.pub_key_pem = pub_pem.decode()
        self.peer_pub_key = None   # RSA public key của đối phương
        self.aes_key: bytes = None # AES session key chung

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _log(self, tag: str, msg: str):
        tags = {"RSA": YELLOW, "AES": GREEN, "SYS": CYAN, "ERR": RED, "IN": MAGENTA}
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
                raise ConnectionError("Server ngắt kết nối")
            raw_len += chunk
        length = int.from_bytes(raw_len, "big")
        raw = b""
        while len(raw) < length:
            chunk = self.conn.recv(min(4096, length - len(raw)))
            if not chunk:
                raise ConnectionError("Server ngắt kết nối")
            raw += chunk
        return json.loads(raw.decode("utf-8"))

    def connect(self):
        self._log("SYS", f"Kết nối tới server {HOST}:{PORT} ...")
        self.conn.connect((HOST, PORT))

        # Gửi HELLO + public key
        self._send({
            "type": "hello",
            "name": self.name,
            "pub_key_pem": self.pub_key_pem,
        })
        self._log("SYS", "Đã gửi public key RSA lên server")

        # Nhận ACK
        ack = self._recv()
        self._log("SYS", f"Server: {ack['msg']}")

    def _do_handshake_as_alice(self):
        """Alice sinh AES key và gửi tới Bob bằng RSA."""
        self._log("SYS", "")
        self._log("SYS", "=== HANDSHAKE: Alice sinh AES session key ===")
        self.aes_key = generate_aes_key(32)
        self._log("AES", f"✓ Sinh AES-256 key ngẫu nhiên:")
        self._log("AES", f"  {pretty_hex(self.aes_key, 32)}")

        self._log("RSA", "Mã hóa AES key bằng RSA public key của Bob ...")
        encrypted = rsa_encrypt(self.peer_pub_key, self.aes_key)
        self._log("RSA", f"✓ AES key sau khi bọc RSA-OAEP ({len(encrypted)} bytes):")
        self._log("RSA", f"  {pretty_hex(encrypted, 32)}")
        self._log("RSA", "  (Chỉ Bob mới giải mã được bằng private key của mình)")

        self._send({
            "type": "aes_key_exchange",
            "encrypted_aes_key": bytes_to_b64(encrypted),
        })
        self._log("SYS", "✓ Đã gửi gói RSA-encrypted AES key qua server → Bob")
        self._log("SYS", "=== Handshake hoàn tất. Có thể chat! ===\n")

    def _do_handshake_as_bob(self, encrypted_key_b64: str):
        """Bob nhận gói RSA và giải mã bằng private key của mình."""
        self._log("SYS", "")
        self._log("SYS", "=== HANDSHAKE: Bob nhận AES key từ Alice ===")
        encrypted = b64_to_bytes(encrypted_key_b64)
        self._log("RSA", f"Nhận gói RSA cipher ({len(encrypted)} bytes) từ Alice qua server:")
        self._log("RSA", f"  {pretty_hex(encrypted, 32)}")
        self._log("RSA", "Giải mã bằng RSA private key của Bob ...")
        self.aes_key = rsa_decrypt(self.private_key, encrypted)
        self._log("AES", f"✓ Giải mã thành công! AES-256 session key:")
        self._log("AES", f"  {pretty_hex(self.aes_key, 32)}")
        self._log("SYS", "=== Handshake hoàn tất. Có thể chat! ===\n")

    def _recv_loop(self):
        """Thread nhận tin nhắn từ server."""
        try:
            while True:
                msg = self._recv()

                if msg["type"] == "peer_pubkey":
                    peer = msg["from"]
                    self._log("RSA", f"Nhận public key RSA của {peer} từ server")
                    self.peer_pub_key = deserialize_public_key(msg["pub_key_pem"].encode())
                    self._log("RSA", f"  {msg['pub_key_pem'][:100].strip()}...")

                    # Alice là người khởi động handshake
                    if self.name == "alice":
                        self._do_handshake_as_alice()

                elif msg["type"] == "aes_key_exchange":
                    # Bob nhận AES key từ Alice
                    if self.name == "bob":
                        self._do_handshake_as_bob(msg["encrypted_aes_key"])

                elif msg["type"] == "chat":
                    if self.aes_key is None:
                        self._log("ERR", "Chưa có AES key, bỏ qua tin nhắn")
                        continue
                    peer = msg["from"]
                    self._log("AES", f"Nhận AES cipher từ {peer}:")
                    self._log("AES", f"  IV:  {msg['iv'][:24]}...")
                    self._log("AES", f"  CT:  {msg['ciphertext'][:36]}...")
                    plaintext = aes_decrypt(self.aes_key, msg["iv"], msg["ciphertext"])
                    peer_color = GREEN if peer == "bob" else CYAN
                    print(f"\n{peer_color}{BOLD}{peer.upper()}{RESET}: {plaintext}")
                    print(f"{self.color}{self.name.upper()}>{RESET} ", end="", flush=True)

                elif msg["type"] == "peer_offline":
                    self._log("SYS", f"{msg['name']} đã ngắt kết nối")

                elif msg["type"] == "ack":
                    pass  # đã xử lý ở connect()

        except ConnectionError:
            self._log("SYS", "Kết nối bị đóng")
        except Exception as e:
            self._log("ERR", f"Lỗi recv: {e}")

    def chat_loop(self):
        """Vòng lặp nhập và gửi tin nhắn."""
        # Khởi động thread nhận
        t = threading.Thread(target=self._recv_loop, daemon=True)
        t.start()

        print(f"{GRAY}Đợi peer kết nối và hoàn tất handshake...{RESET}")
        print(f"{GRAY}Gõ tin nhắn và Enter để gửi. Ctrl+C để thoát.{RESET}\n")

        try:
            while True:
                print(f"{self.color}{self.name.upper()}>{RESET} ", end="", flush=True)
                text = input()

                if not text.strip():
                    continue

                if self.aes_key is None:
                    print(f"{RED}Chưa hoàn tất handshake, đợi thêm...{RESET}")
                    continue

                # Mã hóa AES
                enc = aes_encrypt(self.aes_key, text)
                self._log("AES", f"Mã hóa '{text}' bằng AES-256-CBC:")
                self._log("AES", f"  IV:  {enc['iv'][:24]}...")
                self._log("AES", f"  CT:  {enc['ciphertext'][:36]}...")

                self._send({
                    "type": "chat",
                    "iv": enc["iv"],
                    "ciphertext": enc["ciphertext"],
                })

        except (KeyboardInterrupt, EOFError):
            self._log("SYS", "Thoát.")
            try:
                self._send({"type": "bye"})
            except:
                pass
            self.conn.close()


def main():
    if len(sys.argv) < 2 or sys.argv[1].lower() not in ("alice", "bob"):
        print("Dùng: python client.py alice  hoặc  python client.py bob")
        sys.exit(1)

    name = sys.argv[1].lower()
    client = ChatClient(name)
    client.connect()
    client.chat_loop()


if __name__ == "__main__":
    main()