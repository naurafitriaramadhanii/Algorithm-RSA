"""
Aplikasi Enkripsi & Dekripsi RSA (input p dan q manual) - versi Streamlit
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
from math import gcd

import streamlit as st


# ---------------- Logika RSA ----------------
def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("e tidak punya invers modular terhadap phi(n)")
    return old_s % phi


def generate_keys(p, q, e=None):
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p dan q harus bilangan prima.")
    if p == q:
        raise ValueError("p dan q tidak boleh sama.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if e is None:
        e = 3
        while e < phi and gcd(e, phi) != 1:
            e += 2
        if e >= phi:
            raise ValueError("Tidak ada e yang valid, coba p dan q lain.")
    elif not (1 < e < phi) or gcd(e, phi) != 1:
        raise ValueError(f"e harus 1 < e < {phi} dan koprima dengan phi(n).")
    d = mod_inverse(e, phi)
    return n, phi, e, d


def encrypt(text, e, n):
    codes = [ord(c) for c in text]
    if codes and max(codes) >= n:
        raise ValueError(
            f"n ({n}) terlalu kecil untuk pesan ini. "
            f"Butuh n > {max(codes)}. Gunakan p dan q yang lebih besar."
        )
    return " ".join(str(pow(m, e, n)) for m in codes)


def decrypt(cipher, d, n):
    nums = [int(x) for x in cipher.split()]
    return "".join(chr(pow(c, d, n)) for c in nums)


# ---------------- Tampilan ----------------
st.set_page_config(page_title="Enkripsi & Dekripsi RSA", page_icon="🔐")
st.title("🔐 Enkripsi & Dekripsi RSA")
st.caption("Masukkan sendiri nilai p dan q (bilangan prima).")

st.subheader("1. Input Kunci")
col1, col2, col3 = st.columns(3)
p = col1.number_input("p (prima)", min_value=2, value=1009, step=1)
q = col2.number_input("q (prima)", min_value=2, value=1013, step=1)
e_input = col3.number_input("e (0 = otomatis)", min_value=0, value=0, step=1)

keys = None
try:
    keys = generate_keys(int(p), int(q), int(e_input) or None)
except ValueError as ex:
    st.error(str(ex))

if keys:
    n, phi, e, d = keys
    st.success("Kunci berhasil dibuat.")
    st.code(
        f"n = p x q          = {n}\n"
        f"phi(n) = (p-1)(q-1) = {phi}\n"
        f"Kunci Publik  (e, n) = ({e}, {n})\n"
        f"Kunci Privat  (d, n) = ({d}, {n})"
    )

    tab_enc, tab_dec = st.tabs(["Enkripsi", "Dekripsi"])

    with tab_enc:
        plain = st.text_area("Plaintext", height=120, key="plain")
        if st.button("Enkripsi"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    st.text_area("Ciphertext (salin untuk dekripsi)",
                                 encrypt(plain, e, n), height=120)
                except ValueError as ex:
                    st.error(str(ex))

    with tab_dec:
        cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher")
        if st.button("Dekripsi"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    st.text_area("Plaintext hasil dekripsi",
                                 decrypt(cipher, d, n), height=120)
                except (ValueError, OverflowError):
                    st.error("Ciphertext tidak valid atau kunci (p, q) tidak cocok.")
