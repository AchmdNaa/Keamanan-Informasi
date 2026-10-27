"""
test_aes.py - Membuktikan AES manual sudah benar dengan test vector resmi.
Jalankan: python test_aes.py
"""
import aes

# Test vector FIPS-197 Appendix C (key & plaintext dalam hex)
FIPS = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]
PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")


def run():
    ok = True
    assert aes.SBOX[0x00] == 0x63 and aes.SBOX[0x53] == 0xED, "S-box salah"

    for key_hex, expect in FIPS:
        c = aes.AES(bytes.fromhex(key_hex))
        ct = c.encrypt_block(PLAIN).hex()
        back = c.decrypt_block(bytes.fromhex(ct))
        good = ct == expect and back == PLAIN
        ok &= good
        print(f"AES-{len(key_hex) * 4}: {ct}  {'OK' if good else 'GAGAL'}")

    # Contoh ASCII klasik: key "Thats my Kung Fu", plaintext "Two One Nine Two"
    ct = aes.AES(b"Thats my Kung Fu").encrypt_block(b"Two One Nine Two").hex()
    good = ct == "29c3505f571420f6402299b31a02d73a"
    ok &= good
    print(f"ASCII  : {ct}  {'OK' if good else 'GAGAL'}")

    # Round-trip ECB & CBC dengan berbagai panjang plaintext
    for mode in ("ECB", "CBC"):
        for msg in [b"", b"a", b"Halo Bob!", b"x" * 16, b"panjang " * 9]:
            iv, ct = aes.encrypt(msg, b"Kunci16karakter!", mode)
            ok &= aes.decrypt(ct, b"Kunci16karakter!", mode, iv) == msg
    print("Round-trip ECB/CBC:", "OK" if ok else "GAGAL")
    print("\nSEMUA TES LULUS" if ok else "\nADA TES GAGAL")


if __name__ == "__main__":
    run()
