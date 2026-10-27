"""
protocol.py - Fungsi bantu komunikasi jaringan yang dipakai KDC, Alice, dan Bob.

Format pesan: 1 baris JSON per pesan (diakhiri '\n'), dikirim lewat TCP.
Bagian rahasia selalu dienkripsi AES (manual) lalu ditulis sebagai hex,
jadi di Wireshark yang terlihat hanya hex, bukan isi aslinya.
"""
import json
import secrets
import string

import aes

KEY_CHARS = string.ascii_letters + string.digits


def send_json(sock, obj: dict):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def make_reader(sock):
    return sock.makefile("r", encoding="utf-8", newline="\n")


def recv_json(reader):
    line = reader.readline()
    if not line:
        return None  # koneksi ditutup
    return json.loads(line)


def seal(key: bytes, obj: dict) -> str:
    """Enkripsi sebuah dict dengan AES-CBC. Hasil: hex(IV || ciphertext)."""
    iv, ct = aes.encrypt(json.dumps(obj).encode("ascii"), key, "CBC")
    return (iv + ct).hex()


def unseal(key: bytes, hex_text: str) -> dict:
    """Kebalikan seal(). Melempar ValueError kalau key salah / data rusak."""
    try:
        raw = bytes.fromhex(hex_text)
        pt = aes.decrypt(raw[16:], key, "CBC", raw[:16])
        return json.loads(pt.decode("ascii"))
    except Exception as e:
        raise ValueError("Gagal dekripsi (kemungkinan key tidak cocok)") from e


def random_ascii_key(length: int = 16) -> str:
    """Session key acak berupa huruf/angka ASCII (memenuhi syarat key ASCII)."""
    return "".join(secrets.choice(KEY_CHARS) for _ in range(length))


def new_nonce() -> int:
    """Nonce = angka acak sekali pakai, untuk mencegah replay attack."""
    return secrets.randbelow(10**9)
