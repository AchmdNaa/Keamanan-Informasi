"""
kdc.py - Key Distribution Center (KDC).

Tugas KDC:
- Menyimpan MASTER KEY tiap pengguna (Ka untuk Alice, Kb untuk Bob).
- Menerima permintaan (Langkah 1) dan membalas (Langkah 2) dengan:
    E(Ka, [Ks || ID_A || ID_B || N1])  ->  hanya bisa dibuka Alice
    E(Kb, [Ks || ID_A])                ->  "tiket" untuk Bob, diteruskan oleh Alice

Cara menjalankan:
    python kdc.py --port 5000
Lalu daftarkan master key lewat perintah:  add ALICE <key>   dan   add BOB <key>
"""
import argparse
import socket
import threading
from datetime import datetime

import aes
from protocol import send_json, make_reader, recv_json, seal, random_ascii_key

HELP = """
Perintah KDC:
  add <ID> <key>   daftarkan / ganti master key (ASCII 16/24/32 karakter, boleh ada spasi)
  del <ID>         hapus pengguna
  list             tampilkan pengguna & master key
  ksize <16|24|32> panjang session key yang dibagikan (default 16 = AES-128)
  help             tampilkan bantuan
  quit             matikan KDC
"""


class KDC:
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port
        self.master_keys = {}        # ID -> bytes
        self.session_key_len = 16
        self.lock = threading.Lock()

    def log(self, msg: str):
        print(f"\r[{datetime.now():%H:%M:%S}] {msg}\nKDC> ", end="", flush=True)

    # ---------------- server jaringan ----------------
    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen()
        self.log(f"KDC mendengarkan di {self.host}:{self.port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        with conn:
            try:
                req = recv_json(make_reader(conn))
            except Exception:
                return
            if not req or req.get("type") != "KDC_REQ":
                send_json(conn, {"type": "ERROR", "reason": "permintaan tidak dikenal"})
                return

            id_a, id_b, n1 = req.get("id_a"), req.get("id_b"), req.get("n1")
            self.log(f"[LANGKAH 1] dari {addr[0]}: {id_a} minta session key untuk {id_b} (N1={n1})")

            with self.lock:
                ka, kb = self.master_keys.get(id_a), self.master_keys.get(id_b)
                ks_len = self.session_key_len
            if ka is None or kb is None:
                hilang = id_a if ka is None else id_b
                self.log(f"   ditolak: {hilang} belum terdaftar di KDC")
                send_json(conn, {"type": "ERROR", "reason": f"{hilang} belum terdaftar di KDC"})
                return

            ks = random_ascii_key(ks_len)  # session key baru (ASCII)
            for_a = seal(ka, {"ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1})
            ticket = seal(kb, {"ks": ks, "id_a": id_a})
            send_json(conn, {"type": "KDC_RESP", "for_a": for_a, "ticket": ticket})
            self.log(f"[LANGKAH 2] ke {id_a}: Ks='{ks}' dibungkus E(Ka,..) + tiket E(Kb,..)")

    # ---------------- konsol interaktif ----------------
    def console(self):
        print(HELP)
        while True:
            try:
                line = input("KDC> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            parts = line.split(maxsplit=2)
            cmd = parts[0].lower()
            try:
                if cmd == "add" and len(parts) == 3:
                    key = aes.key_from_ascii(parts[2])
                    with self.lock:
                        self.master_keys[parts[1]] = key
                    print(f"  master key {parts[1]} disimpan ({len(key) * 8}-bit)")
                elif cmd == "del" and len(parts) >= 2:
                    with self.lock:
                        self.master_keys.pop(parts[1], None)
                    print(f"  {parts[1]} dihapus")
                elif cmd == "list":
                    with self.lock:
                        if not self.master_keys:
                            print("  (belum ada pengguna)")
                        for uid, k in self.master_keys.items():
                            print(f"  {uid:<10} '{k.decode()}'")
                    print(f"  panjang session key: {self.session_key_len} karakter")
                elif cmd == "ksize" and len(parts) >= 2 and parts[1] in ("16", "24", "32"):
                    with self.lock:
                        self.session_key_len = int(parts[1])
                    print(f"  session key berikutnya {parts[1]} karakter")
                elif cmd == "help":
                    print(HELP)
                elif cmd == "quit":
                    break
                else:
                    print("  perintah tidak dikenal, ketik 'help'")
            except ValueError as e:
                print(f"  error: {e}")


def main():
    p = argparse.ArgumentParser(description="Key Distribution Center")
    p.add_argument("--host", default="0.0.0.0", help="alamat bind (default semua interface)")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()

    kdc = KDC(args.host, args.port)
    threading.Thread(target=kdc.serve, daemon=True).start()
    kdc.console()


if __name__ == "__main__":
    main()
