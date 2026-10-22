# Keamanan Informasi

Kumpulan tugas dan asistensi mata kuliah Keamanan Informasi, Teknik Informatika ITS.

## Daftar Tugas

| Minggu | Judul | Isi |
|--------|-------|-----|
| 4 | [Saluran Sandi](Asistensi%20Minggu%20Ke%20-%204) | Aplikasi obrolan dengan enkripsi DES |

## Asistensi Minggu 4: Saluran Sandi

Saluran Sandi adalah aplikasi obrolan sederhana berbasis web. Setiap pesan dienkripsi dengan algoritma **DES** (*Data Encryption Standard*) langsung di peramban sebelum dikirim, sehingga server hanya menyimpan *ciphertext* (pesan yang sudah teracak) dan tidak pernah mengetahui kunci maupun isi pesan aslinya.

**Isi folder:**

- `des.js`: implementasi DES dari nol (permutasi awal, pembangkitan 16 subkunci, S-box, dan 16 putaran Feistel).
- `index.html`: tampilan obrolan.
- `server.py`: server HTTP sederhana untuk meneruskan pesan terenkripsi antarperangkat.

**Cara menjalankan:**

1. Pastikan Python 3 terpasang (tidak perlu pustaka tambahan).
2. Jalankan server:
   ```bash
   cd "Asistensi Minggu Ke - 4"
   python3 server.py
   ```
3. Buka alamat yang muncul di terminal, yaitu `http://localhost:8000` di laptop, atau alamat IP lokal di HP yang terhubung ke Wi-Fi yang sama.
4. Masukkan kunci yang sama di kedua perangkat, lalu mulai berkirim pesan.

## Penulis

Achmad Najwa Maruf (5025231265), Teknik Informatika ITS.
