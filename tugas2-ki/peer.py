"""
peer.py - Program untuk ALICE maupun BOB (kodenya sama, dibedakan lewat --id).

Arsitektur: client-client (peer-to-peer).
- Setiap peer membuka port untuk menerima koneksi.
- Peer yang mengetik /connect menjadi INISIATOR (peran "Alice" di skenario),
  peer yang dihubungi menjadi RESPONDER (peran "Bob").
- Setelah 5 langkah key distribution selesai, keduanya bisa mengirim DAN menerima
  pesan terenkripsi AES dengan session key Ks.

Skenario 5 langkah (Stallings, Key Distribution Scenario):
  1. A -> KDC : ID_A || ID_B || N1
  2. KDC -> A : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
  3. A -> B   : E(Kb, [Ks || ID_A])
  4. B -> A   : E(Ks, N2)
  5. A -> B   : E(Ks, f(N2))      dengan f(N2) = N2 + 1

Contoh:
    python peer.py --id ALICE --port 6000 --kdc-ip 192.168.1.10
    python peer.py --id BOB   --port 6000 --kdc-ip 192.168.1.10
"""
import argparse
import socket
import threading

import aes
from protocol import send_json, make_reader, recv_json, seal, unseal, new_nonce

HELP = """
Perintah:
  <teks biasa>                 kirim pesan terenkripsi ke peer
  /connect <ip> <port> <ID>    sambung ke peer lalu jalankan 5 langkah key distribution
  /rekey                       minta session key BARU ke KDC (tanpa restart)
  /master                      ganti master key Anda (harus sama dengan di KDC)
  /kdc <ip> <port>             ganti alamat KDC
  /mode <cbc|ecb>              ganti mode operasi AES untuk pesan
  /enc <key> | <plaintext>     uji enkripsi lokal dengan key bebas (hasil hex)
  /dec <key> | <hex>           uji dekripsi lokal (mode CBC: <key> | <iv hex> | <hex>)
  /trace <key> | <plaintext>   tampilkan isi state AES tiap ronde (blok pertama)
  /verbose <on|off>            tampilkan pesan mentah yang lewat jaringan
  /info                        status koneksi & key
  /quit                        keluar
"""


class Peer:
    def __init__(self, my_id, host, port, kdc_ip, kdc_port, master_key):
        self.my_id = my_id
        self.host, self.port = host, port
        self.kdc_ip, self.kdc_port = kdc_ip, kdc_port
        self.master_key = master_key       # Ka atau Kb (shared dengan KDC)

        self.conn = None                   # socket ke peer
        self.peer_addr = None
        self.peer_id = None
        self.session_key = None            # Ks aktif
        self.pending_ks = None             # Ks yang sedang diverifikasi (langkah 3-5)
        self.pending_n2 = None
        self.mode = "CBC"
        self.verbose = False
        self.send_lock = threading.Lock()

    # ------------------------------------------------------------------
    def log(self, msg: str):
        print(f"\r{msg}\n{self.my_id}> ", end="", flush=True)

    def send(self, obj: dict):
        if not self.conn:
            raise ConnectionError("belum terhubung ke peer")
        with self.send_lock:
            send_json(self.conn, obj)
        if self.verbose:
            self.log(f"  >> kirim: {obj}")

    def attach(self, conn, addr):
        self.conn, self.peer_addr = conn, addr
        self.session_key = self.pending_ks = self.pending_n2 = None
        threading.Thread(target=self.receive_loop, args=(conn,), daemon=True).start()

    # ---------------- listener (menerima koneksi masuk) ----------------
    def listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen()
        self.log(f"[i] {self.my_id} menunggu koneksi di port {self.port}")
        while True:
            c, addr = srv.accept()
            if self.conn:
                send_json(c, {"type": "BUSY"})
                c.close()
                continue
            self.attach(c, addr)
            self.log(f"[+] Koneksi masuk dari {addr[0]}:{addr[1]}")
            self.send({"type": "HELLO", "id": self.my_id})

    # ---------------- inisiator: /connect ----------------
    def connect(self, ip, port, peer_id):
        if self.conn:
            self.log("[!] Sudah terhubung. Keluar dulu atau pakai /rekey.")
            return
        c = socket.create_connection((ip, port), timeout=5)
        c.settimeout(None)
        self.peer_id = peer_id
        self.attach(c, (ip, port))
        self.log(f"[+] Terhubung ke {peer_id} di {ip}:{port}")
        self.send({"type": "HELLO", "id": self.my_id})
        self.start_handshake()

    def start_handshake(self):
        """Langkah 1-3, dijalankan oleh pihak yang memulai (peran Alice)."""
        if not self.conn or not self.peer_id:
            self.log("[!] Belum terhubung ke peer")
            return
        n1 = new_nonce()
        req = {"type": "KDC_REQ", "id_a": self.my_id, "id_b": self.peer_id, "n1": n1}
        self.log(f"[LANGKAH 1] -> KDC {self.kdc_ip}:{self.kdc_port} : {self.my_id} || {self.peer_id} || N1={n1}")
        try:
            with socket.create_connection((self.kdc_ip, self.kdc_port), timeout=5) as k:
                send_json(k, req)
                resp = recv_json(make_reader(k))
        except OSError as e:
            self.log(f"[!] Gagal menghubungi KDC: {e}")
            return

        if not resp or resp.get("type") != "KDC_RESP":
            self.log(f"[!] KDC menolak: {resp.get('reason') if resp else 'tidak ada balasan'}")
            return
        self.log(f"[LANGKAH 2] <- KDC : E(Ka,..) = {resp['for_a'][:48]}...")
        try:
            data = unseal(self.master_key, resp["for_a"])
        except ValueError:
            self.log("[!] Balasan KDC tidak bisa dibuka: master key Anda tidak sama dengan di KDC")
            return
        # cek N1 & ID_B -> memastikan balasan ini memang jawaban untuk permintaan kita (anti-replay)
        if data["n1"] != n1 or data["id_b"] != self.peer_id:
            self.log("[!] N1 / ID_B tidak cocok -> kemungkinan replay attack, dibatalkan")
            return
        self.pending_ks = data["ks"].encode("ascii")
        self.log(f"   Ks diterima: '{data['ks']}' (N1 cocok)")
        self.send({"type": "KEY_TICKET", "ticket": resp["ticket"]})
        self.log(f"[LANGKAH 3] -> {self.peer_id} : tiket E(Kb, Ks || {self.my_id})")

    # ---------------- penerima pesan dari peer ----------------
    def receive_loop(self, conn):
        reader = make_reader(conn)
        try:
            while True:
                msg = recv_json(reader)
                if msg is None:
                    break
                if self.verbose:
                    self.log(f"  << terima: {msg}")
                self.dispatch(msg)
        except (OSError, ValueError) as e:
            self.log(f"[!] Koneksi error: {e}")
        finally:
            if self.conn is conn:
                self.conn = None
                self.session_key = self.pending_ks = None
                self.log(f"[-] Koneksi dengan {self.peer_id} terputus")
                self.peer_id = None

    def dispatch(self, msg):
        t = msg.get("type")

        if t == "HELLO":
            self.peer_id = msg["id"]
            self.log(f"[i] Peer memperkenalkan diri sebagai {self.peer_id}")

        elif t == "KEY_TICKET":                       # saya berperan sebagai Bob
            try:
                tk = unseal(self.master_key, msg["ticket"])
            except ValueError:
                self.log("[!] Tiket tidak bisa dibuka: master key Anda tidak sama dengan di KDC")
                self.send({"type": "HANDSHAKE_FAIL", "reason": "tiket tidak valid"})
                return
            if tk["id_a"] != self.peer_id:
                self.log(f"[!] Tiket untuk {tk['id_a']}, tapi peer mengaku {self.peer_id}. Ditolak.")
                self.send({"type": "HANDSHAKE_FAIL", "reason": "ID tidak cocok"})
                return
            self.pending_ks = tk["ks"].encode("ascii")
            self.pending_n2 = new_nonce()
            self.log(f"[LANGKAH 3] <- {self.peer_id} : tiket dibuka dengan Kb, Ks='{tk['ks']}'")
            self.send({"type": "CHALLENGE", "data": seal(self.pending_ks, {"n2": self.pending_n2})})
            self.log(f"[LANGKAH 4] -> {self.peer_id} : E(Ks, N2) dengan N2={self.pending_n2}")

        elif t == "CHALLENGE":                        # saya berperan sebagai Alice
            try:
                n2 = unseal(self.pending_ks, msg["data"])["n2"]
            except (ValueError, TypeError):
                self.log("[!] Challenge tidak bisa dibuka dengan Ks")
                return
            self.log(f"[LANGKAH 4] <- {self.peer_id} : N2={n2}")
            self.send({"type": "RESPONSE", "data": seal(self.pending_ks, {"fn2": n2 + 1})})
            self.log(f"[LANGKAH 5] -> {self.peer_id} : E(Ks, f(N2)) dengan f(N2)=N2+1={n2 + 1}")

        elif t == "RESPONSE":                         # Bob memverifikasi langkah 5
            try:
                fn2 = unseal(self.pending_ks, msg["data"])["fn2"]
            except (ValueError, TypeError):
                fn2 = None
            if fn2 == self.pending_n2 + 1:
                self.session_key = self.pending_ks
                self.send({"type": "READY"})
                self.log(f"[LANGKAH 5] <- {self.peer_id} : f(N2)={fn2} BENAR.\n"
                         f"[OK] Session key aktif. Silakan ketik pesan.")
            else:
                self.log("[!] f(N2) salah -> handshake gagal")
                self.send({"type": "HANDSHAKE_FAIL", "reason": "f(N2) salah"})

        elif t == "READY":
            self.session_key = self.pending_ks
            self.log(f"[OK] {self.peer_id} memverifikasi Ks. Session key aktif. Silakan ketik pesan.")

        elif t == "HANDSHAKE_FAIL":
            self.log(f"[!] Handshake gagal di sisi peer: {msg.get('reason')}")

        elif t == "MSG":
            self.receive_chat(msg)

        elif t == "BUSY":
            self.log("[!] Peer sedang terhubung dengan pihak lain")

    # ---------------- chat terenkripsi ----------------
    def send_chat(self, text):
        if not self.session_key:
            self.log("[!] Belum ada session key. Jalankan /connect dulu.")
            return
        try:
            data = text.encode("ascii")
        except UnicodeEncodeError:
            self.log("[!] Plaintext harus karakter ASCII")
            return
        iv, ct = aes.encrypt(data, self.session_key, self.mode)
        self.send({"type": "MSG", "mode": self.mode, "iv": iv.hex(), "ct": ct.hex()})
        info = f"  [terkirim, AES-{len(self.session_key) * 8}-{self.mode}] ciphertext (hex): {ct.hex()}"
        if iv:
            info += f"\n  IV (hex): {iv.hex()}"
        self.log(info)

    def receive_chat(self, msg):
        if not self.session_key:
            self.log("[!] Pesan masuk tapi belum ada session key")
            return
        try:
            pt = aes.decrypt(bytes.fromhex(msg["ct"]), self.session_key,
                             msg.get("mode", "CBC"), bytes.fromhex(msg.get("iv", "")))
            text = pt.decode("ascii")
        except (ValueError, UnicodeDecodeError) as e:
            self.log(f"[!] Gagal dekripsi pesan: {e}")
            return
        self.log(f"\n[{self.peer_id}] ciphertext (hex): {msg['ct']}\n"
                 f"[{self.peer_id}] plaintext       : {text}")

    # ---------------- perintah uji lokal ----------------
    @staticmethod
    def split_args(arg, n):
        parts = [p.strip() for p in arg.split("|")]
        if len(parts) != n:
            raise ValueError("format salah, lihat /help")
        return parts

    def cmd_enc(self, arg):
        key_txt, pt = self.split_args(arg, 2)
        iv, ct = aes.encrypt(pt.encode("ascii"), aes.key_from_ascii(key_txt), self.mode)
        print(f"  mode       : AES-{len(key_txt) * 8}-{self.mode}")
        if iv:
            print(f"  IV (hex)   : {iv.hex()}")
        print(f"  cipher hex : {ct.hex()}")

    def cmd_dec(self, arg):
        if self.mode == "CBC":
            key_txt, iv_hex, ct_hex = self.split_args(arg, 3)
            iv = bytes.fromhex(iv_hex)
        else:
            key_txt, ct_hex = self.split_args(arg, 2)
            iv = b""
        pt = aes.decrypt(bytes.fromhex(ct_hex), aes.key_from_ascii(key_txt), self.mode, iv)
        print(f"  plaintext  : {pt.decode('ascii', errors='replace')}")

    def cmd_trace(self, arg):
        key_txt, pt = self.split_args(arg, 2)
        block = aes.pad(pt.encode("ascii"))[:16]
        cipher = aes.AES(aes.key_from_ascii(key_txt))
        print(f"  Plaintext blok 1 : {aes.state_hex(block)}")
        print(f"  Key              : {aes.state_hex(key_txt.encode())}")
        out = cipher.encrypt_block(block, trace=lambda lbl, s: print(f"  {lbl:<24}: {aes.state_hex(s)}"))
        print(f"  Ciphertext blok 1: {out.hex()}")

    def cmd_info(self):
        print(f"  ID saya      : {self.my_id} (port {self.port})")
        print(f"  KDC          : {self.kdc_ip}:{self.kdc_port}")
        print(f"  Master key   : '{self.master_key.decode()}'")
        print(f"  Peer         : {self.peer_id or '-'} {self.peer_addr or ''}")
        sk = f"'{self.session_key.decode()}' (AES-{len(self.session_key) * 8})" if self.session_key else "-"
        print(f"  Session key  : {sk}")
        print(f"  Mode AES     : {self.mode}")

    # ---------------- loop utama ----------------
    def run(self):
        threading.Thread(target=self.listen, daemon=True).start()
        print(HELP)
        while True:
            try:
                line = input(f"{self.my_id}> ")
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip():
                continue
            if not line.startswith("/"):
                try:
                    self.send_chat(line)
                except OSError as e:
                    print(f"  error: {e}")
                continue

            cmd, _, arg = line.partition(" ")
            cmd = cmd.lower()
            try:
                if cmd == "/connect":
                    ip, port, pid = arg.split()
                    self.connect(ip, int(port), pid)
                elif cmd == "/rekey":
                    self.start_handshake()
                elif cmd == "/master":
                    self.master_key = aes.key_from_ascii(input("  Master key baru: "))
                    print("  master key diganti (pastikan KDC juga diupdate dengan 'add')")
                elif cmd == "/kdc":
                    ip, port = arg.split()
                    self.kdc_ip, self.kdc_port = ip, int(port)
                    print(f"  KDC sekarang {ip}:{port}")
                elif cmd == "/mode" and arg.strip().upper() in ("CBC", "ECB"):
                    self.mode = arg.strip().upper()
                    print(f"  mode AES: {self.mode}")
                elif cmd == "/enc":
                    self.cmd_enc(arg)
                elif cmd == "/dec":
                    self.cmd_dec(arg)
                elif cmd == "/trace":
                    self.cmd_trace(arg)
                elif cmd == "/verbose":
                    self.verbose = arg.strip().lower() == "on"
                    print(f"  verbose {'ON' if self.verbose else 'OFF'}")
                elif cmd == "/info":
                    self.cmd_info()
                elif cmd == "/help":
                    print(HELP)
                elif cmd == "/quit":
                    break
                else:
                    print("  perintah tidak dikenal, ketik /help")
            except (ValueError, OSError, UnicodeEncodeError) as e:
                print(f"  error: {e}")
        if self.conn:
            self.conn.close()


def ask_master_key(my_id):
    while True:
        try:
            return aes.key_from_ascii(input(f"Master key {my_id} (16/24/32 karakter ASCII): "))
        except ValueError as e:
            print(f"  {e}")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nDibatalkan.")


def main():
    p = argparse.ArgumentParser(description="Peer Alice/Bob")
    p.add_argument("--id", required=True, help="identitas, misal ALICE atau BOB")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=6000, help="port untuk menerima koneksi peer")
    p.add_argument("--kdc-ip", required=True)
    p.add_argument("--kdc-port", type=int, default=5000)
    args = p.parse_args()

    master = ask_master_key(args.id)
    Peer(args.id, args.host, args.port, args.kdc_ip, args.kdc_port, master).run()


if __name__ == "__main__":
    main()
