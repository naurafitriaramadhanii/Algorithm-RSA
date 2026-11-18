"""
Kalkulator RSA berbasis ASCII (Streamlit)

- Tiap karakter -> kode ASCII 3 digit (mis. 'A' -> 065, spasi -> 032).
- Plaintext dipecah per blok (ukuran blok = jumlah karakter per blok).
- Kode ASCII tiap blok digabung jadi angka m, lalu c = m^e mod n.
- Dekripsi: m = c^d mod n, lalu m dipecah per 3 digit menjadi karakter.

Jalankan lokal: streamlit run app.py
"""

import re
from math import gcd

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Kalkulator RSA", page_icon="🔐", layout="wide")


# ----------------------------------------------------------------------
# Fungsi matematika
# ----------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Miller-Rabin deterministik (aman untuk n < 3,3 x 10^24)."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for sp in small:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def euclid_inverse(e: int, phi: int):
    """Mengembalikan (d, langkah) dengan d = e^-1 mod phi (Euclid diperluas)."""
    steps = []
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        steps.append(f"{old_r} = {q} × {r} + {old_r - q * r}")
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi, steps


def build_key(p: int, q: int, e: int) -> dict:
    if not is_prime(p):
        raise ValueError(f"p = {p} bukan bilangan prima.")
    if not is_prime(q):
        raise ValueError(f"q = {q} bukan bilangan prima.")
    if p == q:
        raise ValueError("p dan q harus berbeda.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not (1 < e < phi):
        raise ValueError(f"e harus memenuhi 1 < e < φ(n) = {phi}.")
    if gcd(e, phi) != 1:
        raise ValueError(f"e = {e} tidak relatif prima dengan φ(n) = {phi} (gcd ≠ 1).")
    d, steps = euclid_inverse(e, phi)
    return {"p": p, "q": q, "e": e, "n": n, "phi": phi, "d": d, "steps": steps}


def parse_int(text: str, name: str) -> int:
    text = (text or "").strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError(f"{name} harus berupa bilangan bulat positif.")
    return int(text)


# ----------------------------------------------------------------------
# Pop up pembangkitan kunci
# ----------------------------------------------------------------------

def render_key(k: dict):
    lines = [
        f"1. Bilangan prima : p = {k['p']}, q = {k['q']}",
        "2. Modulus        : n = p × q",
        f"                      = {k['p']} × {k['q']} = {k['n']}",
        "3. Fungsi Euler   : φ(n) = (p-1)(q-1)",
        f"                      = {k['p'] - 1} × {k['q'] - 1} = {k['phi']}",
        f"4. Kunci publik e : e = {k['e']}",
        "   Cek gcd(e, φ(n)) = 1  ✓",
        "",
        "5. Algoritma Euclid:",
        *[f"     {s}" for s in k["steps"]],
        "",
        f"6. Kunci privat   : d = e⁻¹ mod φ(n) = {k['d']}",
        f"   Cek: e × d mod φ(n) = {(k['e'] * k['d']) % k['phi']}  ✓",
    ]
    st.code("\n".join(lines), language=None)
    c1, c2 = st.columns(2)
    c1.metric("Kunci Publik (e, n)", f"({k['e']}, {k['n']})")
    c2.metric("Kunci Privat (d, n)", f"({k['d']}, {k['n']})")


_dialog = getattr(st, "dialog", None) or getattr(st, "experimental_dialog", None)

if _dialog:
    @_dialog("🔑 Pembangkitan Kunci RSA", width="large")
    def show_key_dialog(k):
        render_key(k)
else:  # fallback untuk Streamlit versi lama
    def show_key_dialog(k):
        with st.expander("🔑 Pembangkitan Kunci RSA", expanded=True):
            render_key(k)


# ----------------------------------------------------------------------
# Halaman
# ----------------------------------------------------------------------

def page_home():
    st.markdown(
        """
        <div style="text-align:center; padding-top:120px;">
            <div style="font-size:64px;">🔐</div>
            <h1 style="font-size:52px; margin-bottom:0;">Kalkulator RSA</h1>
            <h4 style="font-weight:400; margin-top:8px;">Enkripsi &amp; Dekripsi berbasis ASCII</h4>
            <p style="color:#777; margin-top:30px;">
                Selamat datang! Pilih menu <b>Enkripsi</b> atau <b>Dekripsi</b> di samping untuk memulai.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_encrypt():
    st.title("🔒 Enkripsi RSA")

    c1, c2, c3 = st.columns(3)
    p_txt = c1.text_input("p (bilangan prima)", key="enc_p")
    q_txt = c2.text_input("q (bilangan prima)", key="enc_q")
    e_txt = c3.text_input("e (kunci publik)", key="enc_e")

    plain = st.text_area("Plaintext", height=120, key="enc_plain")
    block = st.number_input("Ukuran blok (karakter per blok)", min_value=1, max_value=20,
                            value=1, step=1, key="enc_block")
    show_key = st.checkbox("Tampilkan pop up pembangkitan kunci setelah enkripsi", value=True)

    if st.button("Enkripsi", type="primary"):
        try:
            key = build_key(parse_int(p_txt, "p"), parse_int(q_txt, "q"), parse_int(e_txt, "e"))
            if not plain:
                raise ValueError("Plaintext tidak boleh kosong.")
            bad = [ch for ch in plain if not (1 <= ord(ch) <= 127)]
            if bad:
                raise ValueError(f"Karakter '{bad[0]}' di luar jangkauan ASCII (1-127).")

            n, e, k = key["n"], key["e"], int(block)
            rows, cipher_blocks = [], []
            for i in range(0, len(plain), k):
                chunk = plain[i:i + k]
                digits = "".join(f"{ord(ch):03d}" for ch in chunk)
                m = int(digits)
                if m >= n:
                    raise ValueError(
                        f"Blok ke-{i // k + 1} ('{chunk}') bernilai m = {m} ≥ n = {n}. "
                        "Perkecil ukuran blok atau gunakan p dan q yang lebih besar.")
                c = pow(m, e, n)
                rows.append({"Blok": i // k + 1, "Teks": chunk, "ASCII (m)": digits,
                             "c = m^e mod n": str(c)})
                cipher_blocks.append(str(c))

            st.session_state["enc"] = {"key": key, "rows": rows, "cipher": " ".join(cipher_blocks)}
            st.session_state["enc_open"] = True
        except ValueError as err:
            st.session_state["enc"] = None
            st.error(str(err))

    res = st.session_state.get("enc")
    if res:
        st.subheader("Ciphertext")
        st.code(res["cipher"], language=None)  # ada tombol salin di pojok kanan atas
        st.subheader("Perhitungan per blok")
        st.dataframe(pd.DataFrame(res["rows"]), hide_index=True, use_container_width=True)

        if st.button("🔑 Lihat pembangkitan kunci"):
            show_key_dialog(res["key"])
        elif st.session_state.pop("enc_open", False) and show_key:
            show_key_dialog(res["key"])


def page_decrypt():
    st.title("🔓 Dekripsi RSA")

    c1, c2 = st.columns(2)
    d_txt = c1.text_input("d (kunci privat)", key="dec_d")
    n_txt = c2.text_input("n (modulus)", key="dec_n")
    cipher = st.text_area("Ciphertext (pisahkan tiap blok dengan spasi)", height=120, key="dec_c")

    if st.button("Dekripsi", type="primary"):
        try:
            d = parse_int(d_txt, "d")
            n = parse_int(n_txt, "n")
            if n < 2:
                raise ValueError("n harus lebih besar dari 1.")
            tokens = [t for t in re.split(r"[\s,;]+", cipher.strip()) if t]
            if not tokens:
                raise ValueError("Ciphertext tidak boleh kosong.")
            if not all(t.isdigit() for t in tokens):
                raise ValueError("Ciphertext hanya boleh berisi angka yang dipisah spasi.")

            rows, message, warn = [], [], False
            for i, t in enumerate(tokens, start=1):
                c = int(t)
                if c >= n:
                    raise ValueError(f"Blok ke-{i}: c = {c} harus lebih kecil dari n = {n}.")
                m = pow(c, d, n)
                s = str(m)
                s = s.zfill(-(-len(s) // 3) * 3)  # lengkapi ke kelipatan 3 digit
                codes = [int(s[j:j + 3]) for j in range(0, len(s), 3)]
                chars = ""
                for code in codes:
                    if 32 <= code <= 126 or code in (9, 10, 13):
                        chars += chr(code)
                    else:
                        chars += "?"
                        warn = True
                rows.append({"Blok": i, "Ciphertext (c)": str(c), "m = c^d mod n": str(m),
                             "Kode ASCII": " ".join(f"{x:03d}" for x in codes),
                             "Karakter": chars})
                message.append(chars)

            st.session_state["dec"] = {"rows": rows, "message": "".join(message), "warn": warn}
        except ValueError as err:
            st.session_state["dec"] = None
            st.error(str(err))

    res = st.session_state.get("dec")
    if res:
        st.subheader("Perhitungan per blok")
        st.dataframe(pd.DataFrame(res["rows"]), hide_index=True, use_container_width=True)
        if res["warn"]:
            st.warning("Ada blok yang menghasilkan kode ASCII di luar jangkauan (ditampilkan '?'). "
                       "Periksa kembali nilai d, n, atau ciphertext.")
        st.subheader("Pesan asli")
        st.success(res["message"])


# ----------------------------------------------------------------------
# Navigasi samping
# ----------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🔐 RSA")
    menu = st.radio("Menu", ["🏠 Beranda", "🔒 Enkripsi", "🔓 Dekripsi"], label_visibility="collapsed")

if menu == "🏠 Beranda":
    page_home()
elif menu == "🔒 Enkripsi":
    page_encrypt()
else:
    page_decrypt()
