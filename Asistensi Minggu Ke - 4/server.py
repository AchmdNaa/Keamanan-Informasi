import json
import socket
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8000
FOLDER = Path(__file__).parent
FILE = {"/": ("index.html", "text/html"), "/des.js": ("des.js", "text/javascript")}
pesan = []  # server hanya menyimpan ciphertext, tidak tahu key maupun isi pesan
aktif = {}  # id perangkat -> waktu terakhir terlihat


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/poll":
            q = parse_qs(u.query)
            aktif[q["id"][0]] = time.time()
            online = sum(1 for t in aktif.values() if time.time() - t < 5)
            baru = [m for m in pesan if m["id"] > int(q["since"][0])]
            self.balas(json.dumps({"pesan": baru, "online": online}).encode(), "application/json")
        elif u.path in FILE:                               # kirim halaman web & des.js
            nama, tipe = FILE[u.path]
            self.balas((FOLDER / nama).read_bytes(), tipe + "; charset=utf-8")
        else:
            self.balas(b"", "text/plain", 404)

    def do_POST(self):                                     # terima pesan baru (ciphertext)
        d = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        d["id"] = len(pesan) + 1
        pesan.append(d)
        print(f"[JARINGAN] dari {d['nama']}: {d['c']}")
        self.balas(b"{}", "application/json")

    def balas(self, body, tipe, kode=200):
        self.send_response(kode)
        self.send_header("Content-Type", tipe)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def ip_lan():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "IP-tidak-terdeteksi"


print(f"Buka di Mac : http://localhost:{PORT}")
print(f"Buka di HP  : http://{ip_lan()}:{PORT}")
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()