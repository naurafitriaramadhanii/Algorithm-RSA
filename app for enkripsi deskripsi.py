"""
Kalkulator RSA (input p dan q manual) - versi Streamlit
Tampilan: kartu kafe ala "carrd" (cokelat bergaris, kanopi, tab, pita header).
Memakai kode ASCII (0-127) untuk tiap karakter pesan.
Kode ASCII ditulis 3 digit, disambung, lalu dipisah menjadi blok k digit
(k bisa dipilih: 2, 3, dst.) dan tiap blok diproses dengan RSA.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
from math import gcd, isqrt

import streamlit as st


# ---------------- Logika RSA ----------------
def decrypt_blocks(cipher, d, n, k):
    rows, digits = [], ""
    for token in cipher.split():
        if not token.isdigit():
            raise ValueError("Ciphertext hanya boleh berisi angka dipisah spasi.")
        c = int(token)
        if c >= n:
            raise ValueError("Cipher harus lebih kecil dari n.")
        m = pow(c, d, n)
        if m >= 10 ** k:
            raise ValueError("Blok hasil dekripsi melebihi ukuran blok.")
        blok = str(m).zfill(k)
        rows.append((c, m, blok))
        digits += blok
    codes = []
    for i in range(0, len(digits) // 3 * 3, 3):   # sisa <3 digit = pengisi
        code = int(digits[i:i + 3])
        if code > 127:
            raise ValueError("Hasil bukan kode ASCII, kunci atau ukuran blok tidak cocok.")
        codes.append(code)
    while codes and codes[-1] == 0:                # buang kode 000 pengisi
        codes.pop()
    plain = "".join(chr(c) for c in codes)
    return rows, digits, codes, plain
