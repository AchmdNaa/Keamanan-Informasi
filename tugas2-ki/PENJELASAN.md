# Bahan Belajar untuk Demo

Pemahaman diuji per orang, jadi pastikan bisa menjelaskan bagian ini dengan kata-kata sendiri.

## 1. Gambaran Besar

Masalah: Alice dan Bob ingin memakai AES, tapi AES butuh **key yang sama** di kedua sisi.
Kalau key dikirim begitu saja, penyadap bisa mencurinya.

Solusi: **KDC** (pihak yang dipercaya). Masing-masing sudah punya master key rahasia dengan KDC
(Alice punya Ka, Bob punya Kb). KDC membuat **session key Ks** baru, lalu mengirimkannya
dalam keadaan terenkripsi sehingga hanya Alice dan Bob yang bisa membukanya.

## 2. Lima Langkah dan Alasannya

| Langkah | Isi | Kenapa perlu |
|---|---|---|
| 1 | A → KDC: ID_A, ID_B, N1 | Alice minta Ks untuk bicara dengan Bob. N1 (nonce) = angka acak sekali pakai |
| 2 | KDC → A: E(Ka,[Ks,ID_A,ID_B,N1]) + E(Kb,[Ks,ID_A]) | Bagian pertama hanya bisa dibuka Alice. N1 dicek supaya balasan lama tidak bisa diputar ulang (replay). Bagian kedua = "tiket" untuk Bob, Alice tidak bisa membacanya |
| 3 | A → B: E(Kb,[Ks,ID_A]) | Bob membuka tiket dengan Kb → dapat Ks dan tahu lawan bicaranya Alice |
| 4 | B → A: E(Ks, N2) | Bob menantang: "kalau kamu benar punya Ks, buktikan" |
| 5 | A → B: E(Ks, N2+1) | Alice membuktikan bisa membuka N2. Bob yakin Ks aktif dan bukan rekaman lama |

Kenapa f(N2) = N2+1, bukan N2 saja? Kalau Alice hanya mengirim balik N2 yang sama,
penyerang bisa sekadar memantulkan pesan langkah 4 tanpa membukanya.

## 3. Cara Kerja AES (versi singkat)

AES mengolah blok **16 byte** yang disusun jadi matriks 4×4 (state).
Jumlah ronde: 10 (key 16 byte), 12 (24 byte), 14 (32 byte).

1. **Key Expansion** — key utama dipecah jadi word 4 byte lalu "dikembangkan" menjadi round key untuk tiap ronde
   (pakai RotWord, SubWord, dan konstanta Rcon).
2. **AddRoundKey awal** — state di-XOR dengan round key ke-0.
3. **Setiap ronde**:
   - **SubBytes**: tiap byte diganti lewat S-box (sumber *confusion*, tidak linear).
   - **ShiftRows**: baris ke-r digeser ke kiri r posisi.
   - **MixColumns**: tiap kolom dikali matriks tetap di GF(2^8) (sumber *diffusion*).
   - **AddRoundKey**: XOR dengan round key ronde itu.
4. **Ronde terakhir** tanpa MixColumns.
5. **Dekripsi** = kebalikan semua langkah dalam urutan terbalik (InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns).

Istilah penting:
- **GF(2^8)**: aritmetika byte; tambah = XOR, kali = polinomial modulo 0x11B (fungsi `gmul`).
- **S-box**: di kode ini dihitung, bukan disalin: invers perkalian di GF(2^8) lalu transformasi affine + 0x63.
- **Padding PKCS#7**: kalau kurang n byte dari kelipatan 16, ditambah n byte bernilai n.
- **ECB**: tiap blok dienkripsi terpisah. Plaintext sama → ciphertext sama (pola bocor).
- **CBC**: tiap blok di-XOR dulu dengan ciphertext sebelumnya (blok pertama dengan IV acak),
  jadi pesan yang sama menghasilkan ciphertext berbeda.

## 4. Arsitektur Program

- **TCP socket**, tiap pesan berupa satu baris JSON.
- `kdc.py`: server di port 5000, satu thread per permintaan.
- `peer.py`: satu thread menunggu koneksi, satu thread menerima pesan, thread utama membaca ketikan.
  Arsitektur **client-client**: siapa pun yang `/connect` berperan sebagai Alice.
- Bagian rahasia di jaringan selalu `IV || ciphertext` dalam hex (fungsi `seal`).

## 5. Antisipasi Pertanyaan Dosen

- **Kenapa langkah 1 tidak dienkripsi?** Isinya hanya ID dan nonce, tidak rahasia. Begitulah skenario aslinya.
- **Apa yang terjadi kalau Ka salah?** Alice gagal membuka balasan KDC (padding/JSON tidak valid) → proses berhenti. Bisa didemokan.
- **Kenapa KDC tidak langsung mengirim ke Bob?** Supaya KDC cukup melayani satu permintaan; Alice yang meneruskan tiket.
- **Kelemahan skenario ini?** Jika Ks lama bocor, penyerang bisa memutar ulang langkah 3 (tiket lama) karena Bob tidak tahu umurnya. Perbaikannya: menambah timestamp (Denning–Sacco / Kerberos).
- **Kenapa ciphertext beda tiap kirim pesan yang sama?** Karena mode CBC memakai IV acak.
- **Di mana letak "manual"-nya?** Tidak ada import library kripto; semua operasi AES ada di `aes.py`, protokol KDC di `kdc.py` dan `peer.py`.
- **Bagaimana membuktikan AES-nya benar?** Jalankan `test_aes.py` (test vector FIPS-197), atau bandingkan `/enc` mode ECB dengan alat AES online.

## Referensi

- W. Stallings, *Cryptography and Network Security: Principles and Practice*, bab Key Management and Distribution (Key Distribution Scenario).
- NIST, *FIPS PUB 197: Advanced Encryption Standard (AES)*, 2001 (diperbarui 2023).
- R. Needham dan M. Schroeder, "Using Encryption for Authentication in Large Networks of Computers," *Communications of the ACM*, 1978.
