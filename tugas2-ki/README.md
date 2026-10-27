# Tugas 2 Keamanan Informasi — Key Distribution (KDC) + AES Manual

Implementasi skenario distribusi kunci dengan **KDC, Alice, dan Bob** di tiga IP berbeda.
Setelah langkah ke-5, Alice dan Bob berkomunikasi **dua arah** menggunakan **AES yang diimplementasikan manual**
(tanpa library kriptografi). Hanya memakai pustaka standar Python (`socket`, `threading`, `json`, `secrets`).

## Struktur File

| File | Isi |
|---|---|
| `aes.py` | AES-128/192/256 manual: GF(2^8), S-box dihitung sendiri, key expansion, 4 transformasi ronde, mode ECB/CBC, padding PKCS#7 |
| `kdc.py` | Server KDC: menyimpan master key, membuat session key, menjalankan langkah 1–2 |
| `peer.py` | Program Alice **dan** Bob (dibedakan lewat `--id`): langkah 1–5 + chat terenkripsi |
| `protocol.py` | Fungsi bantu jaringan: kirim/terima JSON, `seal`/`unseal` (enkripsi isi pesan), nonce |
| `test_aes.py` | Uji kebenaran AES dengan test vector resmi FIPS-197 |
| `PENJELASAN.md` | Bahan belajar: konsep AES, KDC, arsitektur, dan antisipasi pertanyaan demo |

## Skenario Key Distribution (5 Langkah)

```
Ka = master key Alice–KDC      Kb = master key Bob–KDC      Ks = session key

1. A  -> KDC : ID_A || ID_B || N1
2. KDC -> A  : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
3. A  -> B   : E(Kb, [Ks || ID_A])
4. B  -> A   : E(Ks, N2)
5. A  -> B   : E(Ks, f(N2))          f(N2) = N2 + 1
-------------------------------------------------------------
6. A <-> B   : E(Ks, pesan)          ciphertext ditampilkan dalam hex
```

## Kebutuhan

- Python 3.8 atau lebih baru (cek dengan `python3 --version` di Mac/Linux atau `python --version` di Windows)
- Tiga perangkat (atau VM) di jaringan yang sama, misalnya satu hotspot/Wi-Fi
- Wireshark di perangkat yang akan dipakai merekam

## Cara Menjalankan (3 Perangkat)

Contoh IP: KDC `192.168.1.10`, Alice `192.168.1.11`, Bob `192.168.1.12`.
Cek IP masing-masing dengan `ipconfig` (Windows) atau `ipconfig getifaddr en0` (Mac).

1. **Uji AES dulu** (di perangkat mana saja):
   ```
   python3 test_aes.py
   ```
2. **Perangkat KDC**:
   ```
   python3 kdc.py --port 5000
   KDC> add ALICE Thats my Kung Fu
   KDC> add BOB KunciRahasiaBob!
   ```
3. **Perangkat Bob**:
   ```
   python3 peer.py --id BOB --port 6000 --kdc-ip 192.168.1.10
   Master key BOB: KunciRahasiaBob!
   ```
4. **Perangkat Alice**:
   ```
   python3 peer.py --id ALICE --port 6000 --kdc-ip 192.168.1.10
   Master key ALICE: Thats my Kung Fu
   ALICE> /connect 192.168.1.12 6000 BOB
   ```
   Langkah 1–5 akan tampil di layar ketiga perangkat. Setelah muncul `[OK] Session key aktif`,
   ketik pesan apa saja di Alice **atau** Bob.

> Di Windows, ganti `python3` dengan `python`. Jika koneksi ditolak, izinkan Python di firewall
> (Windows: pop-up "Allow access"; Mac: System Settings → Network → Firewall).

## Perintah di Program Alice/Bob

| Perintah | Fungsi |
|---|---|
| `<teks>` | kirim pesan terenkripsi |
| `/connect <ip> <port> <ID>` | sambung ke peer + jalankan 5 langkah |
| `/rekey` | minta session key baru ke KDC tanpa restart |
| `/master` | ganti master key sendiri |
| `/kdc <ip> <port>` | ganti alamat KDC |
| `/mode cbc` / `/mode ecb` | ganti mode AES |
| `/enc <key> \| <plaintext>` | uji enkripsi dengan key bebas |
| `/dec <key> \| <hex>` | uji dekripsi (mode CBC: `<key> \| <iv> \| <hex>`) |
| `/trace <key> \| <plaintext>` | tampilkan isi state AES tiap ronde |
| `/verbose on` | tampilkan pesan mentah yang lewat jaringan |
| `/info` | status koneksi dan key |

Perintah KDC: `add <ID> <key>`, `del <ID>`, `list`, `ksize <16|24|32>`, `quit`.

## Contoh Test Case untuk Demo

| Uji | Perintah | Hasil yang diharapkan |
|---|---|---|
| AES benar | `/mode ecb` lalu `/enc Thats my Kung Fu \| Two One Nine Two` | blok pertama `29c3505f571420f6402299b31a02d73a` |
| Ganti key | `/enc KeyBaru123456789 \| Two One Nine Two` | ciphertext berubah total |
| Dekripsi | `/dec Thats my Kung Fu \| 29c3505f...e868` | `Two One Nine Two` |
| Rekey | `/rekey` | session key baru, chat tetap jalan |
| AES-256 | di KDC: `ksize 32` lalu `/rekey` | session key 32 karakter |
| Master key salah | di KDC: `add BOB kunci yg berbeda` lalu `/rekey` | Bob menolak tiket |

## Wireshark

1. Pilih interface yang terhubung ke jaringan demo (Wi-Fi/`en0`/Ethernet). Kalau ketiga program dijalankan
   di satu laptop untuk latihan, pilih **Loopback**.
2. Filter tampilan:
   ```
   tcp.port == 5000 || tcp.port == 6000
   ```
   Untuk satu arah saja, misalnya: `ip.addr == 192.168.1.11 && ip.addr == 192.168.1.12`
3. Klik kanan paket → **Follow → TCP Stream** untuk melihat isi JSON.
   - Ke KDC (langkah 1): `id_a`, `id_b`, `n1` terlihat jelas (memang plaintext sesuai skenario).
   - Langkah 2–5 dan pesan chat: hanya **hex**; session key dan isi pesan tidak terlihat.

## Fitur Tambahan

- AES-192 dan AES-256 selain AES-128
- Mode CBC (IV acak per pesan) dan ECB, bisa diganti saat runtime
- S-box dihitung dari invers GF(2^8) + transformasi affine (bukan tabel salinan)
- `/trace` untuk menampilkan isi state AES per ronde
- `/rekey` dari sisi mana saja; Bob juga bisa menjadi inisiator
- Verifikasi nonce N1 (anti-replay) dan N2 (bukti Alice memegang Ks)
- Deteksi master key salah dan peer yang mengaku ID lain

## Anggota

| Nama | NRP | Kontribusi |
|---|---|---|
| Achmad Najwa Maruf | ... | ... |
| ... | ... | ... |
