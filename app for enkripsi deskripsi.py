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
st.set_page_config(page_title="Enkripsi & Dekripsi RSA", page_icon="🔐", layout="centered")

st.markdown(
    """
<style>
.stApp {
    background: linear-gradient(135deg, #e0f2fe 0%, #f3e8ff 50%, #fce7f3 100%);
}
.hero {
    background: linear-gradient(120deg, #6366f1, #8b5cf6, #ec4899);
    padding: 28px 24px; border-radius: 20px; color: white; text-align: center;
    box-shadow: 0 10px 30px rgba(139, 92, 246, .35); margin-bottom: 18px;
}
.hero h1 { margin: 0; font-size: 2.2rem; color: white; }
.hero p  { margin: 6px 0 0; opacity: .95; font-size: 1.05rem; }
.section-title {
    display: inline-block; background: white; color: #4f46e5;
    padding: 6px 16px; border-radius: 999px; font-weight: 700;
    box-shadow: 0 3px 10px rgba(79, 70, 229, .15); margin: 14px 0 8px;
}
.key-card {
    border-radius: 16px; padding: 16px 18px; color: white;
    box-shadow: 0 6px 18px rgba(0, 0, 0, .15); margin-bottom: 10px;
}
.key-card .label { font-size: .85rem; opacity: .9; letter-spacing: .5px; }
.key-card .value { font-size: 1.15rem; font-weight: 700; word-break: break-all; }
.k-n   { background: linear-gradient(135deg, #f59e0b, #f97316); }
.k-phi { background: linear-gradient(135deg, #10b981, #14b8a6); }
.k-pub { background: linear-gradient(135deg, #3b82f6, #06b6d4); }
.k-prv { background: linear-gradient(135deg, #ec4899, #ef4444); }
.result-box {
    background: white; border-left: 8px solid #8b5cf6; border-radius: 12px;
    padding: 14px 16px; color: #1f2937; word-break: break-all;
    box-shadow: 0 4px 14px rgba(0, 0, 0, .08); margin-top: 8px;
}
.result-box.dec { border-left-color: #10b981; }
.result-title { font-weight: 700; margin-bottom: 4px; color: #6d28d9; }
.result-box.dec .result-title { color: #059669; }
div.stButton > button {
    background: linear-gradient(120deg, #6366f1, #ec4899); color: white;
    border: none; border-radius: 12px; padding: 8px 26px; font-weight: 700;
    box-shadow: 0 5px 14px rgba(236, 72, 153, .35); transition: transform .15s;
}
div.stButton > button:hover { transform: translateY(-2px) scale(1.03); color: white; }
button[data-baseweb="tab"] { font-weight: 700; font-size: 1.05rem; }
</style>
<div class="hero">
    <h1>🔐 Enkripsi & Dekripsi RSA</h1>
    <p>Masukkan sendiri nilai <b>p</b> dan <b>q</b>, lalu amankan pesanmu ✨</p>
</div>
""",
    unsafe_allow_html=True,
)


def key_card(css, label, value):
    return (
        f'<div class="key-card {css}"><div class="label">{label}</div>'
        f'<div class="value">{value}</div></div>'
    )


def result_box(title, text, css=""):
    safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        f'<div class="result-box {css}"><div class="result-title">{title}</div>'
        f"{safe}</div>"
    )


st.markdown('<div class="section-title">🔑 1. Input Kunci</div>', unsafe_allow_html=True)
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
    st.toast("Kunci berhasil dibuat!", icon="✅")

    c1, c2 = st.columns(2)
    c1.markdown(key_card("k-n", "n = p × q", n), unsafe_allow_html=True)
    c2.markdown(key_card("k-phi", "φ(n) = (p-1)(q-1)", phi), unsafe_allow_html=True)
    c3, c4 = st.columns(2)
    c3.markdown(key_card("k-pub", "🔓 Kunci Publik (e, n)", f"({e}, {n})"), unsafe_allow_html=True)
    c4.markdown(key_card("k-prv", "🔒 Kunci Privat (d, n)", f"({d}, {n})"), unsafe_allow_html=True)

    st.markdown('<div class="section-title">💬 2. Pesan</div>', unsafe_allow_html=True)
    tab_enc, tab_dec = st.tabs(["🔐 Enkripsi", "🔓 Dekripsi"])

    with tab_enc:
        plain = st.text_area("Plaintext", height=120, key="plain",
                             placeholder="Ketik pesan rahasiamu di sini...")
        if st.button("🚀 Enkripsi"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    cipher_out = encrypt(plain, e, n)
                    st.markdown(result_box("🔐 Ciphertext", cipher_out), unsafe_allow_html=True)
                    st.caption("Salin angka di atas ke tab Dekripsi.")
                except ValueError as ex:
                    st.error(str(ex))

    with tab_dec:
        cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                              placeholder="Tempel ciphertext di sini...")
        if st.button("🔑 Dekripsi"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    plain_out = decrypt(cipher, d, n)
                    st.markdown(result_box("🔓 Plaintext", plain_out, "dec"), unsafe_allow_html=True)
                    st.balloons()
                except (ValueError, OverflowError):
                    st.error("Ciphertext tidak valid atau kunci (p, q) tidak cocok.")
