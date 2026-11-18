"""
Kalkulator RSA (input p dan q manual) - versi Streamlit
Memakai kode ASCII (0-127) untuk tiap karakter pesan.
Kode ASCII ditulis 3 digit, disambung, lalu dipisah menjadi blok k digit
(k bisa dipilih: 2, 3, dst.) dan tiap blok diproses dengan RSA.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
from math import gcd, isqrt

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
    if n <= 127:
        raise ValueError(
            f"n = {n} terlalu kecil. Untuk kode ASCII (0-127) butuh n > 127, "
            "gunakan p dan q yang lebih besar."
        )
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


def gcd_tries(e_input, phi):
    """Daftar (e, gcd(e, phi)) yang dicoba sampai ketemu e yang koprima."""
    if e_input:
        return [(e_input, gcd(e_input, phi))]
    tries, e = [], 3
    while True:
        g = gcd(e, phi)
        tries.append((e, g))
        if g == 1 or e >= phi:
            return tries
        e += 2


def euclid_steps(e, phi):
    """Tabel extended Euclid untuk mencari d. Baris: (langkah, q, r, s)."""
    rows = [("awal", "-", e, 1), ("awal", "-", phi, 0)]
    old_r, r = e, phi
    old_s, s = 1, 0
    step = 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        step += 1
        rows.append((step, q, r, s))
    return rows, old_r, old_s  # old_r = gcd, old_s = koefisien e


def valid_block_sizes(n, max_k=6):
    """Ukuran blok k (digit) yang valid: nilai blok terbesar 10^k - 1 harus < n."""
    return [k for k in range(2, max_k + 1) if 10 ** k <= n]


def encrypt_blocks(text, e, n, k):
    """
    Tiap karakter -> kode ASCII 3 digit, disambung, dipisah per k digit,
    tiap blok dienkripsi. Return (codes, digits, pad, rows),
    rows = list of (blok_str, m, cipher).
    """
    codes = []
    for ch in text:
        code = ord(ch)
        if code > 127:
            raise ValueError(f"Karakter '{ch}' bukan ASCII (0-127).")
        codes.append(code)
    digits = "".join(f"{c:03d}" for c in codes)
    pad = (-len(digits)) % k
    padded = digits + "0" * pad
    rows = []
    for i in range(0, len(padded), k):
        blok = padded[i:i + k]
        m = int(blok)
        rows.append((blok, m, pow(m, e, n)))
    return codes, digits, pad, rows


def decrypt_blocks(cipher, d, n, k):
    """
    Dekripsi tiap blok, isi nol di kiri sampai k digit, sambung,
    lalu baca per 3 digit sebagai kode ASCII.
    Return (rows, digits, codes, plaintext), rows = list of (c, m, blok_str).
    """
    rows, digits = [], ""
    for c in cipher.split():
        c = int(c)
        if c >= n:
            raise ValueError("Cipher harus lebih kecil dari n.")
        m = pow(c, d, n)
        if m >= 10 ** k:
            raise ValueError("Blok hasil dekripsi melebihi ukuran blok.")
        blok = str(m).zfill(k)
        rows.append((c, m, blok))
        digits += blok
    usable = len(digits) // 3 * 3          # buang sisa digit pengisi
    codes = []
    for i in range(0, usable, 3):
        code = int(digits[i:i + 3])
        if code > 127:
            raise ValueError("Hasil bukan kode ASCII, kunci atau ukuran blok tidak cocok.")
        codes.append(code)
    plain = "".join(chr(c) for c in codes).rstrip("\x00")  # buang pengisi 000
    return rows, digits, codes, plain


# ---------------- Tampilan ----------------
# Palet: Bow #7E2625, Warm Wood #3C1B0F, Candle #F1ECDB, Leaf #868859, Juniper #292F17
st.set_page_config(page_title="Kalkulator RSA", layout="centered")

st.markdown(
    """
<style>
:root {
    --bow: #7E2625; --wood: #3C1B0F; --candle: #F1ECDB;
    --leaf: #868859; --juniper: #292F17;
}
.stApp { background: var(--candle); color: var(--wood); }
h1, h2, h3, label, p { color: var(--wood); }

/* Sidebar */
section[data-testid="stSidebar"] { background: var(--juniper); }
section[data-testid="stSidebar"] * { color: var(--candle) !important; }
.side-title { font-size: 1.3rem; font-weight: 800; margin-bottom: 2px; }
.side-sub { font-size: .9rem; opacity: .85; margin-bottom: 14px; }

/* Welcome */
.hero {
    background: linear-gradient(120deg, var(--juniper), var(--wood) 55%, var(--bow));
    padding: 38px 24px; border-radius: 20px; color: var(--candle); text-align: center;
    box-shadow: 0 10px 26px rgba(60, 27, 15, .35); margin-bottom: 18px;
    border-bottom: 6px solid var(--leaf);
}
.hero .welcome { margin: 0 0 4px; font-size: 1rem; letter-spacing: 3px;
    text-transform: uppercase; opacity: .85; color: var(--candle); }
.hero h1 { margin: 0; font-size: 2.6rem; color: var(--candle); }
.hero p  { margin: 8px 0 0; opacity: .95; font-size: 1.05rem; color: var(--candle); }

.section-title {
    display: inline-block; background: var(--juniper); color: var(--candle);
    padding: 6px 16px; border-radius: 999px; font-weight: 700;
    box-shadow: 0 3px 10px rgba(41, 47, 23, .25); margin: 14px 0 8px;
}
.key-card {
    border-radius: 16px; padding: 16px 18px; color: var(--candle);
    box-shadow: 0 6px 16px rgba(60, 27, 15, .22); margin-bottom: 10px;
}
.key-card .label { font-size: .85rem; opacity: .9; letter-spacing: .5px; }
.key-card .value { font-size: 1.15rem; font-weight: 700; word-break: break-all; }
.k-pub { background: var(--juniper); }
.k-prv { background: var(--bow); }
.step {
    background: #fffdf6; border-left: 8px solid var(--leaf); border-radius: 12px;
    padding: 12px 16px; margin: 10px 0; color: var(--wood);
    box-shadow: 0 4px 14px rgba(60, 27, 15, .10);
}
.step.s2 { border-left-color: var(--bow); }
.step.s3 { border-left-color: var(--juniper); }
.step.s4 { border-left-color: var(--wood); }
.step .st-title { font-weight: 700; color: var(--juniper); margin-bottom: 4px; }
.step .st-calc { font-family: monospace; font-size: 1.02rem; word-break: break-all; }
.step .st-note { font-size: .9rem; opacity: .85; margin-top: 4px; }
.step .ok { color: var(--juniper); font-weight: 700; }
.result-box {
    background: #fffdf6; border-left: 8px solid var(--bow); border-radius: 12px;
    padding: 14px 16px; color: var(--wood); word-break: break-all;
    box-shadow: 0 4px 14px rgba(60, 27, 15, .12); margin-top: 8px;
}
.result-box.dec { border-left-color: var(--leaf); }
.result-title { font-weight: 700; margin-bottom: 4px; color: var(--bow); }
.result-box.dec .result-title { color: var(--juniper); }
.tbl-wrap { max-height: 300px; overflow-y: auto; margin-top: 10px; border-radius: 12px;
    box-shadow: 0 4px 14px rgba(60, 27, 15, .12); }
table.steps { width: 100%; border-collapse: collapse; background: #fffdf6; }
table.steps th { background: var(--juniper); color: var(--candle); padding: 8px 10px;
    position: sticky; top: 0; text-align: center; }
table.steps td { padding: 6px 10px; text-align: center; color: var(--wood);
    border-bottom: 1px solid #e3dcc3; font-family: monospace; }
table.steps tr:nth-child(even) td { background: #f6f1e0; }
div.stButton > button {
    background: var(--bow); color: var(--candle); border: 2px solid var(--wood);
    border-radius: 12px; padding: 8px 26px; font-weight: 700;
    box-shadow: 0 5px 12px rgba(126, 38, 37, .35); transition: transform .15s;
}
div.stButton > button:hover {
    transform: translateY(-2px); background: var(--wood); color: var(--candle);
    border-color: var(--leaf);
}
</style>
""",
    unsafe_allow_html=True,
)


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def section(title):
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)


def key_card(css, label, value):
    return (
        f'<div class="key-card {css}"><div class="label">{label}</div>'
        f'<div class="value">{value}</div></div>'
    )


def result_box(title, text, css=""):
    return (
        f'<div class="result-box {css}"><div class="result-title">{title}</div>'
        f"{esc(text)}</div>"
    )


def table(headers, rows):
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>" for r in rows
    )
    return (
        f'<div class="tbl-wrap"><table class="steps"><tr>{head}</tr>{body}</table></div>'
    )


def step_box(title, calc, note="", css=""):
    note_html = f'<div class="st-note">{note}</div>' if note else ""
    return (
        f'<div class="step {css}"><div class="st-title">{title}</div>'
        f'<div class="st-calc">{calc}</div>{note_html}</div>'
    )


def block_size_picker(n, key):
    """Pilihan ukuran blok (digit) yang valid untuk n."""
    sizes = valid_block_sizes(n)
    k = st.radio(
        "Pesan dipisah menjadi blok berapa digit?",
        sizes,
        index=sizes.index(3) if 3 in sizes else 0,
        horizontal=True,
        format_func=lambda x: f"{x} digit",
        key=key,
    )
    st.caption(
        f"Nilai blok terbesar ({10 ** k - 1}) harus lebih kecil dari n = {n}, "
        f"jadi untuk n ini ukuran blok maksimal {sizes[-1]} digit. "
        "Ukuran blok yang sama harus dipakai saat enkripsi dan dekripsi."
    )
    return k


def render_key_generation(p, q, e_input, n, phi, e, d):
    """Semua langkah pembangkitan kunci (dipakai di dalam expander)."""
    st.markdown(
        step_box(
            "Langkah 1 - Pastikan p dan q bilangan prima",
            f"p = {p} &rarr; prima &nbsp;|&nbsp; q = {q} &rarr; prima",
            f'Tidak habis dibagi bilangan 2 sampai {isqrt(p)} (untuk p) dan 2 sampai '
            f'{isqrt(q)} (untuk q), serta p &ne; q. <span class="ok">Valid</span>',
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box(
            "Langkah 2 - Hitung n",
            f"n = p &times; q = {p} &times; {q} = <b>{n}</b>",
            f'Syarat ASCII: n &gt; 127 &rarr; {n} &gt; 127 <span class="ok">Terpenuhi</span>',
            "s2",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box(
            "Langkah 3 - Hitung &phi;(n)",
            f"&phi;(n) = (p &minus; 1) &times; (q &minus; 1) = {p - 1} &times; {q - 1} = <b>{phi}</b>",
            css="s3",
        ),
        unsafe_allow_html=True,
    )

    tries = gcd_tries(int(e_input), phi)
    mode = "dimasukkan manual" if e_input else "dipilih otomatis (bilangan ganjil terkecil &gt; 1)"
    st.markdown(
        step_box(
            "Langkah 4 - Pilih e",
            f"Syarat: 1 &lt; e &lt; &phi;(n) dan FPB(e, &phi;(n)) = 1 &rarr; e = <b>{e}</b>",
            f"e {mode}.",
            "s4",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        table(
            ["e yang dicoba", f"FPB(e, {phi})", "Koprima?"],
            [(te, g, "Ya" if g == 1 else "Tidak") for te, g in tries],
        ),
        unsafe_allow_html=True,
    )

    rows_eu, g, coef = euclid_steps(e, phi)
    st.markdown(
        step_box(
            "Langkah 5 - Hitung d (invers modular)",
            f"e &times; d &equiv; 1 (mod &phi;(n)) &rarr; {e} &times; d &equiv; 1 (mod {phi})",
            "Dihitung dengan algoritma Euclid yang diperluas. Kolom s adalah koefisien e; "
            f"FPB akhir = {g}, s terakhir sebelum sisa 0 = {coef}.",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        table(["Langkah", "q (hasil bagi)", "r (sisa)", "s"], rows_eu),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box(
            "Hasil d",
            f"d = {coef} mod {phi} = <b>{d}</b>",
            f'Verifikasi: e &times; d mod &phi;(n) = {e} &times; {d} mod {phi} = '
            f'{(e * d) % phi} <span class="ok">Benar (harus 1)</span>',
            "s3",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box(
            "Langkah 6 - Kunci yang dihasilkan",
            f"Kunci Publik (e, n) = <b>({e}, {n})</b><br>"
            f"Kunci Privat (d, n) = <b>({d}, {n})</b>",
            "Kunci publik dipakai untuk enkripsi, kunci privat untuk dekripsi.",
            "s2",
        ),
        unsafe_allow_html=True,
    )


# ---------------- Halaman Enkripsi ----------------
def page_enkripsi():
    section("Input Enkripsi")
    col1, col2, col3 = st.columns(3)
    p = int(col1.number_input("p (prima)", min_value=2, value=1009, step=1, key="enc_p"))
    q = int(col2.number_input("q (prima)", min_value=2, value=1013, step=1, key="enc_q"))
    e_input = int(col3.number_input("e (0 = otomatis)", min_value=0, value=0, step=1, key="enc_e"))

    try:
        n, phi, e, d = generate_keys(p, q, e_input or None)
    except ValueError as ex:
        st.error(str(ex))
        return

    plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                         placeholder="Ketik pesan rahasiamu di sini...")
    k = block_size_picker(n, "enc_blok")

    if st.button("Enkripsi"):
        if not plain:
            st.warning("Isi plaintext dulu.")
            return
        try:
            codes, digits, pad, rows = encrypt_blocks(plain, e, n, k)
        except ValueError as ex:
            st.error(str(ex))
            return

        # 1. Pembangkitan kunci (bisa ditampilkan / disembunyikan)
        section("Pembangkitan Kunci")
        with st.expander("Klik untuk menampilkan / menyembunyikan langkah pembangkitan kunci"):
            render_key_generation(p, q, e_input, n, phi, e, d)
        st.markdown(
            key_card("k-pub", "Kunci Publik (e, n)", f"({e}, {n})"),
            unsafe_allow_html=True,
        )

        # 2. Pemisahan blok + tabel
        section("Pemisahan Blok")
        kode_str = " ".join(f"{c:03d}" for c in codes)
        blok_str = " | ".join(r[0] for r in rows)
        note = (
            f"Blok terakhir ditambah {pad} angka 0 di belakang agar genap {k} digit."
            if pad else ""
        )
        st.markdown(
            step_box(
                f"Pemisahan blok ({k} digit)",
                f"Kode ASCII (3 digit): {kode_str}<br>"
                f"Digit disambung: {digits}<br>"
                f"Dipisah per {k} digit: {blok_str}",
                note,
            ),
            unsafe_allow_html=True,
        )
        with st.expander("Klik untuk menampilkan tabel perhitungan per blok"):
            st.markdown(
                table(
                    ["Blok", "Nilai (m)", f"Cipher (m^{e} mod {n})"],
                    [(b, m, c) for b, m, c in rows],
                ),
                unsafe_allow_html=True,
            )

        # 3. Ciphertext
        section("Hasil")
        cipher_out = " ".join(str(r[2]) for r in rows)
        st.markdown(result_box("Ciphertext", cipher_out), unsafe_allow_html=True)
        st.caption(
            f"Untuk dekripsi, gunakan kunci privat (d, n) = ({d}, {n}) "
            f"dan ukuran blok {k} digit."
        )


# ---------------- Halaman Dekripsi ----------------
def page_dekripsi():
    section("Input Dekripsi")
    col1, col2 = st.columns(2)
    d = col1.number_input("d (kunci privat)", min_value=1, value=None, step=1,
                          placeholder="mis. 816077", key="dec_d")
    n = col2.number_input("n", min_value=1, value=None, step=1,
                          placeholder="mis. 1022117", key="dec_n")

    cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                          placeholder="Tempel ciphertext di sini...")

    if d is None or n is None:
        st.info("Isi d dan n terlebih dahulu.")
        return
    d, n = int(d), int(n)
    if n <= 127:
        st.error("n harus lebih besar dari 127 untuk kode ASCII.")
        return

    k = block_size_picker(n, "dec_blok")

    if st.button("Dekripsi"):
        if not cipher.strip():
            st.warning("Isi ciphertext dulu.")
            return
        try:
            rows, digits, codes, plain_out = decrypt_blocks(cipher, d, n, k)
        except (ValueError, OverflowError):
            st.error(
                "Ciphertext tidak valid, atau kunci (d, n) dan ukuran blok tidak cocok "
                "dengan saat enkripsi."
            )
            return

        # 1. Perhitungan tiap blok
        section("Perhitungan Setiap Blok")
        st.markdown(
            table(
                ["Cipher (c)", f"Nilai (c^{d} mod {n})", f"Blok ({k} digit)"],
                rows,
            ),
            unsafe_allow_html=True,
        )

        # 2. Penyambungan blok -> ASCII
        section("Penyambungan Blok")
        kode_str = " ".join(f"{c:03d}" for c in codes)
        usable = len(codes) * 3
        note = (
            f"{len(digits) - usable} digit pengisi di akhir dibuang."
            if len(digits) > usable else ""
        )
        st.markdown(
            step_box(
                "Blok disambung lalu dibaca per 3 digit",
                f"Digit disambung: {digits}<br>Kode ASCII: {kode_str}",
                note,
                "s2",
            ),
            unsafe_allow_html=True,
        )

        # 3. Pesan asli
        section("Hasil")
        st.markdown(result_box("Pesan asli (Plaintext)", plain_out, "dec"), unsafe_allow_html=True)


# ---------------- Sidebar + Welcome ----------------
with st.sidebar:
    st.markdown('<div class="side-title">Kalkulator RSA</div>'
                '<div class="side-sub">Pilih mode yang ingin dipakai</div>',
                unsafe_allow_html=True)
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], label_visibility="collapsed")

st.markdown(
    """
<div class="hero">
    <div class="welcome">Selamat Datang di</div>
    <h1>Kalkulator RSA</h1>
    <p>Enkripsi dan dekripsi pesan dengan kode <b>ASCII</b> &middot; p dan q kamu tentukan sendiri</p>
</div>
""",
    unsafe_allow_html=True,
)

if mode == "Enkripsi":
    page_enkripsi()
else:
    page_dekripsi()
