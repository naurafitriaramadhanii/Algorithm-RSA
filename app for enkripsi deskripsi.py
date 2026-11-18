"""
Aplikasi Enkripsi & Dekripsi RSA (input p dan q manual) - versi Streamlit
Memakai kode ASCII (0-127) untuk tiap karakter pesan.
Kode ASCII ditulis 3 digit, disambung, lalu dipisah menjadi blok k digit
(k bisa dipilih: 2, 3, dst.) dan tiap blok dienkripsi dengan RSA.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
Tampilan: gaya dashboard krem/cokelat (sidebar tan + kartu rounded).
"""
from math import gcd, isqrt

import streamlit as st


# ---------------- Logika RSA (tidak diubah) ----------------
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
    Return (rows, plaintext), rows = list of (cipher, blok_str).
    """
    rows, digits = [], ""
    for c in cipher.split():
        m = pow(int(c), d, n)
        if m >= 10 ** k:
            raise ValueError("Blok hasil dekripsi melebihi ukuran blok.")
        blok = str(m).zfill(k)
        rows.append((int(c), blok))
        digits += blok
    usable = len(digits) // 3 * 3          # buang sisa digit pengisi
    chars = []
    for i in range(0, usable, 3):
        code = int(digits[i:i + 3])
        if code > 127:
            raise ValueError("Hasil bukan kode ASCII, kunci atau ukuran blok tidak cocok.")
        chars.append(chr(code))
    plain = "".join(chars).rstrip("\x00")  # buang pengisi 000 di akhir
    return rows, plain


# ---------------- Tampilan ----------------
# Palet dashboard: Beige #EBE6DB, Cream #F4F1EA, Tan #B5A68C, Cocoa #3A2A1F,
# Green #2E8B3D, Red #C0392B
st.set_page_config(page_title="Enkripsi & Dekripsi RSA", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');
:root {
    --bg: #ebe6db; --panel: #eeeae1; --card: #f6f3ec; --line: #ddd5c4;
    --tan: #b5a68c; --tan-dark: #8f7f66; --cocoa: #3a2a1f;
    --green: #2e8b3d; --red: #c0392b; --muted: #7a6c5c;
}
html, body, [class*="css"], .stApp { font-family: 'Poppins', 'Segoe UI', sans-serif; }
#MainMenu, footer, header[data-testid="stHeader"] { visibility: hidden; height: 0; }
.stApp {
    background-color: var(--bg);
    background-image: radial-gradient(ellipse 70% 95% at 100% 105%, #f5f3ee 0 62%, transparent 63%);
    color: var(--cocoa);
}
.block-container {
    max-width: 1080px; padding: 2rem 2.2rem 2.5rem; margin-top: 1.6rem;
    background: var(--panel); border-radius: 30px;
    box-shadow: 0 18px 40px rgba(58, 42, 31, .18);
}
h1, h2, h3, label, p, span, div { color: var(--cocoa); }

/* ---- Sidebar (tan) ---- */
section[data-testid="stSidebar"] {
    background: var(--tan); border-radius: 0 30px 30px 0; min-width: 300px;
    box-shadow: 8px 0 24px rgba(58, 42, 31, .12);
}
section[data-testid="stSidebar"] > div { padding-top: 1rem; }
section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span, section[data-testid="stSidebar"] div { color: var(--cocoa); }
section[data-testid="stSidebar"] div[data-baseweb="input"] {
    background: #f3efe6; border: none; border-radius: 14px;
}
section[data-testid="stSidebar"] div[data-baseweb="input"] input { background: transparent; color: var(--cocoa); }
section[data-testid="stSidebar"] [data-testid="stNumberInputContainer"] { background: #f3efe6; border-radius: 14px; border: none; }
section[data-testid="stSidebar"] button[data-testid="stNumberInputStepDown"],
section[data-testid="stSidebar"] button[data-testid="stNumberInputStepUp"] { background: transparent; color: var(--cocoa); }
.brand { text-align: center; margin: 6px 0 18px; }
.avatar {
    width: 84px; height: 84px; border-radius: 50%; margin: 0 auto 10px;
    background: radial-gradient(circle at 35% 30%, #fbf8f1, #e4d9c3);
    border: 4px solid #d9cdb5; display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 1.25rem; color: var(--cocoa);
    box-shadow: 0 6px 14px rgba(58, 42, 31, .22);
}
.brand .name { font-weight: 700; font-size: 1.05rem; color: var(--cocoa); }
.brand .sub { font-size: .78rem; color: #4d3b2c; opacity: .85; }
.section-title {
    display: inline-block; background: var(--cocoa); color: #f4f1ea !important;
    padding: 6px 18px; border-radius: 999px; font-weight: 600; font-size: .85rem;
    box-shadow: 0 4px 10px rgba(58, 42, 31, .25); margin: 14px 0 8px;
}
section[data-testid="stSidebar"] .section-title { color: #f4f1ea; }

/* ---- Header ---- */
.top-label { font-weight: 700; font-size: 1rem; letter-spacing: .3px; color: var(--cocoa); }
.top-title { font-weight: 700; font-size: 1.9rem; margin: 10px 0 2px; color: var(--cocoa); }
.top-sub { font-size: .88rem; color: var(--muted); margin-bottom: 16px; }
.top-sub b { color: var(--cocoa); }

/* ---- Tabs jadi pill ---- */
div[data-baseweb="tab-list"] { gap: 8px; background: transparent; }
div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] { display: none; }
button[data-baseweb="tab"] {
    background: var(--card); border-radius: 999px; padding: 6px 20px; height: auto;
    border: 1px solid var(--line); font-weight: 600; font-size: .95rem; color: var(--cocoa);
}
button[data-baseweb="tab"][aria-selected="true"] { background: var(--cocoa); border-color: var(--cocoa); }
button[data-baseweb="tab"][aria-selected="true"] p { color: #f4f1ea; }

/* ---- Kartu kunci ---- */
.key-card {
    border-radius: 22px; padding: 16px 20px; color: #f4f1ea;
    box-shadow: 0 8px 18px rgba(58, 42, 31, .18); margin: 12px 0;
}
.key-card .label { font-size: .82rem; opacity: .85; letter-spacing: .4px; color: #f4f1ea; }
.key-card .value { font-size: 1.2rem; font-weight: 700; word-break: break-all; color: #f4f1ea; }
.k-pub { background: var(--cocoa); }
.k-prv { background: var(--tan-dark); }

/* ---- Langkah ---- */
.step {
    --accent: var(--tan);
    background: var(--card); border: 1px solid var(--line); border-radius: 20px;
    padding: 14px 18px; margin: 10px 0; color: var(--cocoa);
    box-shadow: 0 4px 12px rgba(58, 42, 31, .08);
}
.step.s2 { --accent: var(--cocoa); }
.step.s3 { --accent: var(--green); }
.step.s4 { --accent: var(--red); border: 2px solid var(--cocoa); }
.step .st-title { font-weight: 600; color: var(--cocoa); margin-bottom: 6px; }
.step .st-title::before {
    content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent); margin-right: 10px;
}
.step .st-calc { font-family: monospace; font-size: 1rem; word-break: break-all; }
.step .st-note { font-size: .86rem; color: var(--muted); margin-top: 6px; }
.step .ok { color: var(--green); font-weight: 700; }
.step .ok::before { content: "\\2713  "; }

/* ---- Hasil ---- */
.result-box {
    background: var(--card); border: 2px solid var(--cocoa); border-radius: 22px;
    padding: 14px 18px; color: var(--cocoa); word-break: break-all;
    box-shadow: 0 6px 16px rgba(58, 42, 31, .12); margin-top: 10px;
}
.result-box.dec { border-color: var(--green); }
.result-title { font-weight: 700; margin-bottom: 4px; color: var(--cocoa); }
.result-box.dec .result-title { color: var(--green); }

/* ---- Tabel ---- */
.tbl-wrap { max-height: 300px; overflow-y: auto; margin-top: 12px; border-radius: 20px;
    border: 1px solid var(--line); box-shadow: 0 4px 12px rgba(58, 42, 31, .08); }
table.steps { width: 100%; border-collapse: collapse; background: var(--card); }
table.steps th { background: var(--cocoa); color: #f4f1ea; padding: 9px 10px;
    position: sticky; top: 0; text-align: center; font-weight: 600; font-size: .85rem; }
table.steps td { padding: 7px 10px; text-align: center; color: var(--cocoa);
    border-bottom: 1px solid var(--line); font-family: monospace; }
table.steps tr:nth-child(even) td { background: #efeadf; }

/* ---- Input & tombol ---- */
div[data-baseweb="textarea"] { background: var(--card); border-radius: 18px; border: 1px solid var(--line); }
div[data-baseweb="textarea"] textarea { background: transparent; color: var(--cocoa); }
div.stButton > button {
    background: var(--cocoa); color: #f4f1ea; border: 2px solid var(--cocoa);
    border-radius: 14px; padding: 8px 28px; font-weight: 600;
    box-shadow: 0 5px 12px rgba(58, 42, 31, .28); transition: transform .15s;
}
div.stButton > button p { color: #f4f1ea; }
div.stButton > button:hover {
    transform: translateY(-2px); background: var(--tan-dark); border-color: var(--tan-dark);
}
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="top-label">RSA Dashboard</div>
<div class="top-title">Enkripsi &amp; Dekripsi RSA</div>
<div class="top-sub">Masukkan sendiri nilai <b>p</b> dan <b>q</b> &middot; berbasis kode <b>ASCII</b></div>
""",
    unsafe_allow_html=True,
)


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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


# ---------------- Sidebar: 1. Input kunci + 2. Ukuran blok ----------------
keys = None
with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="avatar">RSA</div>'
        '<div class="name">RSA Calculator</div>'
        '<div class="sub">ASCII &middot; blok k digit</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-title">Input Kunci</div>', unsafe_allow_html=True)
    p = st.number_input("p (prima)", min_value=2, value=1009, step=1)
    q = st.number_input("q (prima)", min_value=2, value=1013, step=1)
    e_input = st.number_input("e (0 = otomatis)", min_value=0, value=0, step=1)

    try:
        keys = generate_keys(int(p), int(q), int(e_input) or None)
    except ValueError as ex:
        st.error(str(ex))

    if keys:
        n, phi, e, d = keys
        p, q = int(p), int(q)

        st.markdown('<div class="section-title">Ukuran Blok</div>', unsafe_allow_html=True)
        sizes = valid_block_sizes(n)
        k = st.radio(
            "Pesan dipisah menjadi blok berapa digit?",
            sizes,
            index=sizes.index(3) if 3 in sizes else 0,
            horizontal=True,
            format_func=lambda x: f"{x} digit",
            key="blok",
        )
        st.caption(
            f"Nilai blok terbesar ({10 ** k - 1}) harus lebih kecil dari n = {n}, "
            f"jadi untuk n ini ukuran blok maksimal {sizes[-1]} digit. "
            "Ukuran blok yang sama harus dipakai saat enkripsi dan dekripsi."
        )

# ---------------- Konten utama ----------------
if keys:
    # ---------------- Tab: Pembangkitan Kunci | Enkripsi | Dekripsi ----------------
    tab_key, tab_enc, tab_dec = st.tabs(["Pembangkitan Kunci", "Enkripsi", "Dekripsi"])

    # ---- Tab Pembangkitan Kunci: semua perhitungan kunci ----
    with tab_key:
        # Langkah 1: cek prima
        st.markdown(
            step_box(
                "Langkah 1 - Pastikan p dan q bilangan prima",
                f"p = {p} &rarr; prima &nbsp;|&nbsp; q = {q} &rarr; prima",
                f'Tidak habis dibagi bilangan 2 sampai {isqrt(p)} (untuk p) dan 2 sampai '
                f'{isqrt(q)} (untuk q), serta p &ne; q. <span class="ok">Valid</span>',
            ),
            unsafe_allow_html=True,
        )

        # Langkah 2: n
        st.markdown(
            step_box(
                "Langkah 2 - Hitung n",
                f"n = p &times; q = {p} &times; {q} = <b>{n}</b>",
                f'Syarat ASCII: n &gt; 127 &rarr; {n} &gt; 127 <span class="ok">Terpenuhi</span>',
                "s2",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 3: phi
        st.markdown(
            step_box(
                "Langkah 3 - Hitung &phi;(n)",
                f"&phi;(n) = (p &minus; 1) &times; (q &minus; 1) = {p - 1} &times; {q - 1} = <b>{phi}</b>",
                css="s3",
            ),
            unsafe_allow_html=True,
        )

        # Langkah 4: pilih e
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

        # Langkah 5: hitung d
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

        # Langkah 6: ringkasan kunci
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

    # ---- Tab Enkripsi: hanya kunci publik ----
    with tab_enc:
        st.markdown(
            key_card("k-pub", "Kunci Publik (e, n)", f"({e}, {n})"),
            unsafe_allow_html=True,
        )
        plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                             placeholder="Ketik pesan rahasiamu di sini...")
        if st.button("Enkripsi"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    codes, digits, pad, rows = encrypt_blocks(plain, e, n, k)
                    cipher_out = " ".join(str(r[2]) for r in rows)

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
                    st.markdown(result_box("Ciphertext", cipher_out), unsafe_allow_html=True)
                    st.caption(f"Salin angka di atas ke tab Dekripsi (ukuran blok tetap {k} digit).")
                    st.markdown(
                        table(
                            ["Blok", "Nilai (m)", f"Cipher (m^{e} mod {n})"],
                            [(b, m, c) for b, m, c in rows],
                        ),
                        unsafe_allow_html=True,
                    )
                except ValueError as ex:
                    st.error(str(ex))

    # ---- Tab Dekripsi: hanya kunci privat ----
    with tab_dec:
        st.markdown(
            key_card("k-prv", "Kunci Privat (d, n)", f"({d}, {n})"),
            unsafe_allow_html=True,
        )
        cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                              placeholder="Tempel ciphertext di sini...")
        if st.button("Dekripsi"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    rows, plain_out = decrypt_blocks(cipher, d, n, k)
                    st.markdown(result_box("Plaintext", plain_out, "dec"), unsafe_allow_html=True)
                    st.markdown(
                        table(
                            ["Cipher (c)", f"Blok (c^{d} mod {n}, {k} digit)"],
                            rows,
                        ),
                        unsafe_allow_html=True,
                    )
                except (ValueError, OverflowError):
                    st.error(
                        "Ciphertext tidak valid, atau kunci (p, q) dan ukuran blok tidak cocok "
                        "dengan saat enkripsi."
                    )
