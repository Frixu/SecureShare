# tests/manual_test.py

import json
import socket
import ssl
import uuid
import time
import base64
import hashlib
import hmac as hmac_lib

HOST = "127.0.0.1"
PORT = 9999

def compute_hmac(msg: dict, secret: bytes) -> str:
    msg_copy = {**msg, "hmac": ""}
    raw = json.dumps(msg_copy, sort_keys=True, separators=(",", ":")).encode()
    return hmac_lib.new(secret, raw, hashlib.sha256).hexdigest()

def make_msg(msg_type, session_id="", payload=None, msg_id=None, secret=None):
    msg = {
        "type":       msg_type,
        "session_id": session_id,
        "msg_id":     msg_id or str(uuid.uuid4()),
        "timestamp":  int(time.time()),
        "payload":    payload or {},
        "hmac":       "",
    }
    if secret:
        msg["hmac"] = compute_hmac(msg, secret)
    return msg

def send(sock, msg):
    raw = json.dumps(msg, separators=(",", ":")) + "\n"
    sock.sendall(raw.encode())

def recv(sock):
    buf = b""
    while b"\n" not in buf:
        buf += sock.recv(4096)
    return json.loads(buf.split(b"\n")[0])

# --- Połączenie ---
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = ctx.wrap_socket(socket.socket(), server_hostname=HOST)
sock.connect((HOST, PORT))
print("✓ Połączono z serwerem")

# --- HELLO ---
send(sock, make_msg("HELLO", payload={"client_version": "1.0"}))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: ACK)")

# --- AUTH ---
send(sock, make_msg("AUTH", payload={"username": "alice", "password": "haslo123"}))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: AUTH_OK)")
assert resp["type"] == "AUTH_OK", f"AUTH nieudany: {resp}"
session_id = resp["payload"]["session_id"]

# Odczytaj hmac_secret z AUTH_OK
hmac_secret_b64 = resp["payload"].get("hmac_secret")
if hmac_secret_b64:
    secret = base64.b64decode(hmac_secret_b64)
else:
    secret = None
print(f"  session_id={session_id[:12]}… | hmac_secret={'tak' if secret else 'brak — dodaj do AUTH_OK'}")

# --- PING ---
send(sock, make_msg("PING", session_id=session_id, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: PONG)")

# --- UPLOAD ---
content   = b"Hello, SecureShare! To jest testowy plik."
checksum  = hashlib.sha256(content).hexdigest()
chunk_b64 = base64.b64encode(content).decode()

send(sock, make_msg("UPLOAD_START", session_id, {
    "filename": "test.txt",
    "filesize": len(content),
    "checksum": checksum,
}, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: ACK) — UPLOAD_START")

send(sock, make_msg("UPLOAD_CHUNK", session_id, {
    "chunk_index": 0,
    "data": chunk_b64,
}, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: ACK) — UPLOAD_CHUNK")

send(sock, make_msg("UPLOAD_END", session_id, {
    "filename":     "test.txt",
    "total_chunks": 1,
}, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: ACK) — UPLOAD_END")

# --- DOWNLOAD ---
send(sock, make_msg("DOWNLOAD_REQUEST", session_id, {"filename": "test.txt"}, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: DOWNLOAD_CHUNK)")
data = base64.b64decode(resp["payload"]["data"])
print(f"  Odebrano: '{data.decode()}'")

# --- BYE ---
send(sock, make_msg("BYE", session_id, secret=secret))
resp = recv(sock)
print(f"← {resp['type']} (oczekiwano: ACK) — BYE")

sock.close()
print("\n✓ Wszystkie testy przeszły!")