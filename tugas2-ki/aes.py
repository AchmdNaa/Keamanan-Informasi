"""
aes.py - Implementasi AES MANUAL (tanpa library kriptografi), mengikuti standar FIPS-197.

Mendukung:
- AES-128 / AES-192 / AES-256 (key 16 / 24 / 32 karakter ASCII)
- Mode ECB dan CBC
- Padding PKCS#7

Istilah singkat:
- State      : blok 16 byte yang sedang diproses, dibayangkan sebagai matriks 4x4
               yang diisi per KOLOM (indeks = baris + 4 * kolom).
- Round key  : kunci turunan untuk tiap ronde, dihasilkan dari key utama (Key Expansion).
- GF(2^8)    : "aritmetika byte" khusus AES. Penjumlahan = XOR,
               perkalian = perkalian polinomial modulo 0x11B.
"""
import secrets

BLOCK_SIZE = 16


# =====================================================================
# 1. Aritmetika GF(2^8)
# =====================================================================
def xtime(a: int) -> int:
    """Kali 2 di GF(2^8): geser kiri 1 bit; kalau tembus 8 bit, XOR dengan 0x11B."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def gmul(a: int, b: int) -> int:
    """Perkalian dua byte di GF(2^8) (metode 'kali dua lalu jumlahkan')."""
    hasil = 0
    while b:
        if b & 1:
            hasil ^= a
        a = xtime(a)
        b >>= 1
    return hasil


def ginv(a: int) -> int:
    """Invers perkalian di GF(2^8): a^254 (karena a^255 = 1). Invers 0 didefinisikan 0."""
    if a == 0:
        return 0
    hasil, basis, e = 1, a, 254
    while e:  # pangkat cepat (square-and-multiply)
        if e & 1:
            hasil = gmul(hasil, basis)
        basis = gmul(basis, basis)
        e >>= 1
    return hasil


# =====================================================================
# 2. S-Box DIHITUNG sendiri (bukan tabel copy-paste)
#    S(x) = affine( invers(x) )
# =====================================================================
def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        b = ginv(x)
        # transformasi affine: b XOR rotl1 XOR rotl2 XOR rotl3 XOR rotl4 XOR 0x63
        sbox[x] = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()

# Rcon: konstanta ronde untuk key expansion (01, 02, 04, 08, ..., dihitung dengan xtime)
RCON = [0x01]
while len(RCON) < 14:
    RCON.append(xtime(RCON[-1]))


# =====================================================================
# 3. Empat operasi dasar AES (dan kebalikannya)
# =====================================================================
def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # baris r digeser ke KIRI sebanyak r posisi
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    # baris r digeser ke KANAN sebanyak r posisi
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(s):
    # tiap kolom dikali matriks [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] di GF(2^8)
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3,
            a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3,
            a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3),
            gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2),
        ]
    return out


def inv_mix_columns(s):
    # matriks invers [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
            gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
            gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
            gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14),
        ]
    return out


def add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


# =====================================================================
# 4. Kelas AES: key expansion + enkripsi/dekripsi 1 blok
# =====================================================================
class AES:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Panjang key harus 16, 24, atau 32 byte")
        self.nk = len(key) // 4      # jumlah word (4 byte) di key: 4/6/8
        self.nr = self.nk + 6        # jumlah ronde: 10/12/14
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes):
        nk, nr = self.nk, self.nr
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]             # RotWord
                temp = [SBOX[b] for b in temp]         # SubWord
                temp[0] ^= RCON[i // nk - 1]           # XOR Rcon
            elif nk > 6 and i % nk == 4:               # aturan tambahan khusus AES-256
                temp = [SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        # gabungkan tiap 4 word menjadi 1 round key (16 byte)
        return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]

    def encrypt_block(self, block: bytes, trace=None) -> bytes:
        """trace (opsional) = fungsi(label, state) untuk menampilkan isi state tiap langkah."""
        t = trace or (lambda *_: None)
        s = add_round_key(list(block), self.round_keys[0])
        t("Ronde 0  AddRoundKey", s)
        for r in range(1, self.nr):
            s = sub_bytes(s);                          t(f"Ronde {r:<2} SubBytes", s)
            s = shift_rows(s);                         t(f"Ronde {r:<2} ShiftRows", s)
            s = mix_columns(s);                        t(f"Ronde {r:<2} MixColumns", s)
            s = add_round_key(s, self.round_keys[r]);  t(f"Ronde {r:<2} AddRoundKey", s)
        # ronde terakhir TANPA MixColumns
        s = sub_bytes(s);                              t(f"Ronde {self.nr} SubBytes", s)
        s = shift_rows(s);                             t(f"Ronde {self.nr} ShiftRows", s)
        s = add_round_key(s, self.round_keys[self.nr]); t(f"Ronde {self.nr} AddRoundKey", s)
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = add_round_key(list(block), self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            s = inv_shift_rows(s)
            s = inv_sub_bytes(s)
            s = add_round_key(s, self.round_keys[r])
            s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, self.round_keys[0])
        return bytes(s)


# =====================================================================
# 5. Padding + mode operasi (ECB / CBC)
# =====================================================================
def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE   # selalu 1..16
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (kemungkinan key salah)")
    return data[:-n]


def encrypt(plaintext: bytes, key: bytes, mode: str = "CBC", iv: bytes = None):
    """Mengembalikan (iv, ciphertext). Untuk ECB, iv = b''."""
    cipher = AES(key)
    data = pad(plaintext)
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    out = b""
    if mode == "ECB":
        for b in blocks:
            out += cipher.encrypt_block(b)
        return b"", out
    # CBC: tiap blok di-XOR dengan ciphertext blok sebelumnya (blok pertama dengan IV)
    iv = iv or secrets.token_bytes(16)
    prev = iv
    for b in blocks:
        prev = cipher.encrypt_block(bytes(x ^ y for x, y in zip(b, prev)))
        out += prev
    return iv, out


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes = b"") -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % 16:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte")
    cipher = AES(key)
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    out = b""
    if mode == "ECB":
        for b in blocks:
            out += cipher.decrypt_block(b)
    else:
        prev = iv
        for b in blocks:
            out += bytes(x ^ y for x, y in zip(cipher.decrypt_block(b), prev))
            prev = b
    return unpad(out)


def key_from_ascii(text: str) -> bytes:
    """Validasi key ASCII (16/24/32 karakter) lalu ubah ke bytes."""
    if not all(32 <= ord(ch) < 127 for ch in text):
        raise ValueError("Key hanya boleh berisi karakter ASCII yang bisa diketik")
    if len(text) not in (16, 24, 32):
        raise ValueError(f"Panjang key {len(text)} karakter; harus 16, 24, atau 32")
    return text.encode("ascii")


def state_hex(s) -> str:
    return " ".join(f"{b:02x}" for b in s)
