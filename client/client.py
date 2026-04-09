import socket
import threading
import json
import sys
import os
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    rsa_encrypt, rsa_decrypt,
    generate_aes_key, aes_encrypt, aes_decrypt,
    bytes_to_b64, b64_to_bytes,
    rsa_sign, rsa_verify
)

HOST = "127.0.0.1"

USE_ATTACKER = False
USE_SIGNATURE = False

if len(sys.argv) >= 3 and sys.argv[2] == "mitm":
    USE_ATTACKER = True

if len(sys.argv) >= 4 and sys.argv[3] == "secure":
    USE_SIGNATURE = True

if USE_ATTACKER and sys.argv[1] == "alice":
    PORT = 5555
else:
    PORT = 65432


class ChatClient:
    def __init__(self, name):
        self.name = name
        self.running = True

        print(f"\n=== {name.upper()} ===")

        if USE_ATTACKER:
            print(" MITM MODE")
        if USE_SIGNATURE:
            print(" SIGNATURE ENABLED")

        self.private_key, self.public_key = generate_rsa_keypair()
        self.pub_key_pem = serialize_public_key(self.public_key).decode()

        self.peer_pub_key = None
        self.aes_key = None

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send(self, data):
        raw = json.dumps(data).encode()
        self.conn.sendall(len(raw).to_bytes(4, "big") + raw)

    def recv(self):
        raw_len = self.conn.recv(4)
        if not raw_len:
            raise ConnectionError

        length = int.from_bytes(raw_len, "big")

        raw = b""
        while len(raw) < length:
            raw += self.conn.recv(4096)

        return json.loads(raw.decode())

    def connect(self):
        self.conn.connect((HOST, PORT))

        self.send({
            "type": "hello",
            "name": self.name,
            "pub_key_pem": self.pub_key_pem,
        })

        print(self.recv()["msg"])

    # ─── FIX: terminate() đúng thứ tự, chặn double-call, unblock input() ───
    def terminate(self, reason):
        if not self.running:
            return  # tránh gọi terminate 2 lần

        self.running = False  # chặn chat_loop NGAY, trước mọi thứ khác

        print(f"\n TERMINATED: {reason}")

        try:
            self.send({
                "type": "terminate",
                "reason": reason
            })
        except Exception:
            pass

        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        try:
            self.conn.close()
        except Exception:
            pass

        # SIGINT để unblock input() đang blocking ở main thread
        # sau đó os._exit(1) hard-kill toàn process
        os.kill(os.getpid(), signal.SIGINT)
        os._exit(1)

    def recv_loop(self):
        try:
            while self.running:
                msg = self.recv()

                # nhận lệnh kill từ server
                if msg["type"] == "terminate":
                    print(f"\n SERVER STOP: {msg['reason']}")
                    self.running = False
                    os._exit(0)

                elif msg["type"] == "peer_pubkey":
                    self.peer_pub_key = deserialize_public_key(
                        msg["pub_key_pem"].encode()
                    )

                    if self.name == "alice":
                        self.aes_key = generate_aes_key()
                        encrypted = rsa_encrypt(self.peer_pub_key, self.aes_key)

                        self.send({
                            "type": "aes_key_exchange",
                            "encrypted_aes_key": bytes_to_b64(encrypted)
                        })

                elif msg["type"] == "aes_key_exchange":
                    if self.name == "bob":
                        encrypted = b64_to_bytes(msg["encrypted_aes_key"])
                        self.aes_key = rsa_decrypt(self.private_key, encrypted)

                elif msg["type"] == "chat":
                    if not self.aes_key:
                        continue

                    # VERIFY SIGNATURE
                    if USE_SIGNATURE:
                        if "signature" not in msg:
                            self.terminate("MITM DETECTED (NO SIGNATURE)")
                            return  # ← đảm bảo không chạy tiếp sau terminate

                        payload = msg["iv"] + msg["ciphertext"]
                        sig = b64_to_bytes(msg["signature"])

                        if not rsa_verify(self.peer_pub_key, sig, payload.encode()):
                            self.terminate("MITM DETECTED (INVALID SIGNATURE)")
                            return  # ← đảm bảo không chạy tiếp sau terminate

                    text = aes_decrypt(self.aes_key, msg["iv"], msg["ciphertext"])
                    print(f"\n{msg['from']}: {text}")

        except Exception:
            # Chỉ terminate nếu process vẫn đang chạy (tránh loop)
            if self.running:
                self.terminate("Connection lost")

    def chat_loop(self):
        threading.Thread(target=self.recv_loop, daemon=True).start()

        while self.running:
            try:
                text = input("> ")

                # ← FIX: kiểm tra lại running sau khi input() unblock
                if not self.running:
                    break

                if not self.aes_key:
                    print("Wait handshake...")
                    continue

                enc = aes_encrypt(self.aes_key, text)

                data = {
                    "type": "chat",
                    "iv": enc["iv"],
                    "ciphertext": enc["ciphertext"],
                }

                if USE_SIGNATURE:
                    payload = enc["iv"] + enc["ciphertext"]
                    sig = rsa_sign(self.private_key, payload.encode())
                    data["signature"] = bytes_to_b64(sig)

                self.send(data)

            except (KeyboardInterrupt, EOFError):
                break
            except Exception:
                break


def main():
    name = sys.argv[1]
    client = ChatClient(name)
    client.connect()
    client.chat_loop()


if __name__ == "__main__":
    main()