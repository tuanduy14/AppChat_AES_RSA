"""
server.py — Server trung gian xử lý RSA handshake và relay tin nhắn AES.

Luồng hoạt động:
  1. Client kết nối, gửi RSA public key của mình.
  2. Server lưu public key và broadcast cho client kia.
  3. Một client (Alice) gửi AES session key đã được mã hóa bằng RSA public key của Bob.
  4. Server relay gói tin đó sang Bob (không thể giải mã vì không có private key của Bob).
  5. Từ đó mọi tin nhắn chat đều là AES-encrypted, server chỉ relay mù.

Chạy: python server.py
"""

import socket
import threading
import json
import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.crypto_utils import pretty_hex, b64_to_bytes

HOST = "127.0.0.1"
PORT = 65432

# Trạng thái toàn cục của server
clients: dict = {}       # {name: {"conn": socket, "pub_key_pem": str, "addr": tuple}}
lock = threading.Lock()


def log(tag: str, msg: str, color: str = ""):
    colors = {"RSA": "\033[93m", "AES": "\033[92m", "SYS": "\033[96m", "ERR": "\033[91m", "": "\033[0m"}
    reset = "\033[0m"
    c = colors.get(tag, "")
    print(f"{c}[{tag}]{reset} {msg}")


def send_json(conn: socket.socket, data: dict):
    """Gửi JSON có độ dài cố định prefix."""
    raw = json.dumps(data).encode("utf-8")
    length = len(raw)
    conn.sendall(length.to_bytes(4, "big") + raw)


def recv_json(conn: socket.socket) -> dict:
    """Nhận JSON có độ dài cố định prefix."""
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng")
        raw_len += chunk
    length = int.from_bytes(raw_len, "big")
    raw = b""
    while len(raw) < length:
        chunk = conn.recv(min(4096, length - len(raw)))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng")
        raw += chunk
    return json.loads(raw.decode("utf-8"))


def broadcast_peer_key(sender_name: str):
    """Gửi public key của sender sang peer (nếu peer đã kết nối)."""
    with lock:
        sender = clients.get(sender_name)
        if not sender:
            return
        for name, info in clients.items():
            if name != sender_name:
                try:
                    send_json(info["conn"], {
                        "type": "peer_pubkey",
                        "from": sender_name,
                        "pub_key_pem": sender["pub_key_pem"],
                    })
                    log("RSA", f"Đã gửi public key của {sender_name} → {name}")
                except Exception as e:
                    log("ERR", f"Không gửi được public key tới {name}: {e}")


def handle_client(conn: socket.socket, addr):
    name = None
    try:
        # Bước 1: nhận HELLO + public key
        msg = recv_json(conn)
        assert msg["type"] == "hello"
        name = msg["name"]
        pub_key_pem = msg["pub_key_pem"]

        with lock:
            clients[name] = {"conn": conn, "pub_key_pem": pub_key_pem, "addr": addr}

        log("SYS", f"{name} kết nối từ {addr[0]}:{addr[1]}")
        log("RSA", f"Nhận public key từ {name}:\n       {pub_key_pem[:64].strip()}...")

        # Xác nhận đã nhận key
        send_json(conn, {"type": "ack", "msg": f"Xin chào {name}! Server đã lưu public key của bạn."})

        # Gửi public key của mình cho peer (nếu peer đã online)
        broadcast_peer_key(name)

        # Nếu peer đã online, gửi public key của peer cho mình
        with lock:
            for pname, pinfo in clients.items():
                if pname != name:
                    send_json(conn, {
                        "type": "peer_pubkey",
                        "from": pname,
                        "pub_key_pem": pinfo["pub_key_pem"],
                    })
                    log("RSA", f"Gửi public key của {pname} → {name} (peer đã online trước)")

        # Vòng lặp nhận tin
        while True:
            msg = recv_json(conn)

            if msg["type"] == "aes_key_exchange":
                # RSA-encrypted AES key từ Alice → Bob (server relay, không giải mã được)
                encrypted_key_b64 = msg["encrypted_aes_key"]
                encrypted_bytes = b64_to_bytes(encrypted_key_b64)
                log("RSA", f"[KEY EXCHANGE] {name} → ??? (AES key bọc RSA)")
                log("RSA", f"  Gói RSA cipher: {pretty_hex(encrypted_bytes)}")
                log("RSA", f"  Server KHÔNG thể giải mã (không có private key của người nhận)")

                # Relay sang peer
                with lock:
                    for pname, pinfo in clients.items():
                        if pname != name:
                            send_json(pinfo["conn"], {
                                "type": "aes_key_exchange",
                                "from": name,
                                "encrypted_aes_key": encrypted_key_b64,
                            })
                            log("RSA", f"  Relay gói RSA → {pname}")

            elif msg["type"] == "chat":
                # AES-encrypted message — server chỉ thấy cipher
                iv = msg["iv"]
                ciphertext = msg["ciphertext"]
                cipher_bytes = b64_to_bytes(ciphertext)
                log("AES", f"[CHAT] {name} → ??? (AES-256-CBC)")
                log("AES", f"  IV:         {pretty_hex(b64_to_bytes(iv))}")
                log("AES", f"  Ciphertext: {pretty_hex(cipher_bytes)}")
                log("AES", f"  Server KHÔNG thể đọc nội dung (không có AES key)")

                # Relay sang peer
                with lock:
                    for pname, pinfo in clients.items():
                        if pname != name:
                            send_json(pinfo["conn"], {
                                "type": "chat",
                                "from": name,
                                "iv": iv,
                                "ciphertext": ciphertext,
                            })
                            log("AES", f"  Relay AES cipher → {pname}")

            elif msg["type"] == "bye":
                log("SYS", f"{name} ngắt kết nối")
                break

    except (ConnectionError, json.JSONDecodeError, AssertionError) as e:
        log("ERR", f"Lỗi với {name or addr}: {e}")
    finally:
        with lock:
            if name and name in clients:
                del clients[name]
        conn.close()
        if name:
            # Thông báo peer rằng đối phương offline
            with lock:
                for pname, pinfo in clients.items():
                    try:
                        send_json(pinfo["conn"], {"type": "peer_offline", "name": name})
                    except:
                        pass


def main():
    log("SYS", f"╔══════════════════════════════════════╗")
    log("SYS", f"║   AES + RSA Chat — SERVER            ║")
    log("SYS", f"╚══════════════════════════════════════╝")
    log("SYS", f"Lắng nghe tại {HOST}:{PORT} ...")
    log("SYS", "Server chỉ relay, không thể đọc nội dung chat (end-to-end encrypted)\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(2)

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("SYS", "\nServer tắt.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()