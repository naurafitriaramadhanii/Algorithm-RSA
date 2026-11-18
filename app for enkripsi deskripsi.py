"""
Kalkulator RSA (input p dan q manual) - versi Streamlit
Tampilan: kartu kafe ala "carrd" (cokelat bergaris, kanopi, tab, pita header).
Memakai kode ASCII (0-127) untuk tiap karakter pesan.
Kode ASCII ditulis 3 digit, disambung, lalu dipisah menjadi blok k digit
dan tiap blok diproses dengan RSA.

Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
from math import gcd, isqrt

import streamlit as st

MAX_DIGITS = 300  # batas panjang angka input agar aplikasi tetap responsif


# ---------------- Logika RSA ----------------
def is_prime(n):
    """Uji prima: pembagian kecil + Miller-Rabin (deterministik untuk n < 3,3e24)."""
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
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
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
    return rows, old_r, old_s


def valid_block_sizes(n, max_k=10):
    """Ukuran blok k (digit) yang valid: nilai blok terbesar 10^k - 1 harus < n."""
    return [k for k in range(2, max_k + 1) if 10 ** k <= n]


def encrypt_blocks(text, e, n, k):
    """Return (codes, digits, pad, rows), rows = list of (blok_str, m, cipher)."""
    bad = sorted({ch for ch in text if ord(ch) > 127})
    if bad:
        raise ValueError(
            "Karakter bukan ASCII (0-127): " + " ".join(f"'{c}'" for c in bad[:10])
        )
    codes = [ord(ch) for ch in text]
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
    """Return (rows, digits, codes, plaintext), rows = list of (c, m, blok_str)."""
    tokens = cipher.replace(",", " ").split()
    if not tokens:
        raise ValueError("Ciphertext kosong.")
    rows, digits = [], ""
    for tok in tokens:
        if not tok.isdigit():
            raise ValueError(f"'{tok[:20]}' bukan angka.")
        c = int(tok)
        if c >= n:
            raise ValueError(f"Blok cipher {c} harus lebih kecil dari n = {n}.")
        m = pow(c, d, n)
        if m >= 10 ** k:
            raise ValueError("Blok hasil dekripsi melebihi ukuran blok.")
        blok = str(m).zfill(k)
        rows.append((c, m, blok))
        digits += blok
    usable = len(digits) // 3 * 3
    codes = []
    for i in range(0, usable, 3):
        code = int(digits[i:i + 3])
        if code > 127:
            raise ValueError("Hasil bukan kode ASCII, kunci atau ukuran blok tidak cocok.")
        codes.append(code)
    plain = "".join(chr(c) for c in codes).rstrip("\x00")
    return rows, digits, codes, plain


def parse_int(text, name, minimum=0):
    """Ubah teks jadi int dengan pesan error yang jelas."""
    s = (text or "").strip().replace(" ", "")
    if not s:
        raise ValueError(f"{name} belum diisi.")
    if not s.isdigit():
        raise ValueError(f"{name} harus berupa bilangan bulat positif.")
    if len(s) > MAX_DIGITS:
        raise ValueError(f"{name} terlalu panjang (maksimal {MAX_DIGITS} digit).")
    v = int(s)
    if v < minimum:
        raise ValueError(f"{name} minimal {minimum}.")
    return v


# ---------------- Tampilan ----------------
st.set_page_config(
    page_title="Kalkulator RSA",
    page_icon="🥐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Itim&family=Mali:wght@400;600;700&display=swap');

:root {
    --choc: #6a4332; --choc-dark: #4b2d20; --milk: #b08a5b;
    --cream: #fdf4de; --butter: #f6e4b0; --butter-edge: #d9b878;
    --leaf: #9bb05a; --leaf-dark: #6f8438; --paper: #fffaf0; --ink: #5a3a2a;
    --pad: 26px;
}

.stApp {
    background-color: #f3ead0;
    background-image:
        repeating-linear-gradient(0deg, rgba(190,175,120,.22) 0 22px, transparent 22px 44px),
        repeating-linear-gradient(90deg, rgba(190,175,120,.22) 0 22px, transparent 22px 44px);
    font-family: 'Mali', 'Trebuchet MS', sans-serif;
    color: var(--ink);
}
header[data-testid="stHeader"], footer, #MainMenu,
section[data-testid="stSidebar"], div[data-testid="stSidebarCollapsedControl"],
div[data-testid="collapsedControl"] { display: none !important; }

.block-container, div[data-testid="stMainBlockContainer"] {
    max-width: 800px;
    margin: 28px auto;
    padding: 0 var(--pad) var(--pad) !important;
    background: repeating-linear-gradient(90deg, #6d4735 0 4px, #5f3d2d 4px 8px);
    border: 10px solid var(--choc-dark);
    border-radius: 42px;
    box-shadow: 0 0 0 4px #fdf4de, 0 14px 30px rgba(75,45,32,.35);
    overflow: hidden;
}
.stApp h1, .stApp h2, .stApp h3, .stApp p, .stApp label, .stApp span, .stApp li {
    font-family: 'Mali', sans-serif;
}

/* Kanopi + badge */
.awning {
    display: flex; gap: 0; margin: 0 calc(var(--pad) * -1); height: 78px;
    border-bottom: 6px solid var(--choc-dark); background: var(--choc-dark);
}
.awning span {
    flex: 1; height: 72px; border-radius: 0 0 30px 30px;
    border: 3px solid var(--choc-dark); border-top: 0;
}
.awning span:nth-child(odd)  { background: #fdebc8; }
.awning span:nth-child(even) { background: var(--leaf); }
.welcome-wrap { height: 0; position: relative; z-index: 5; }
.welcome-badge {
    position: absolute; left: 50%; top: -92px; transform: translateX(-50%);
    background: var(--choc); border: 4px solid var(--choc-dark);
    outline: 3px dashed #c9a27a; outline-offset: -11px;
    border-radius: 26px; padding: 12px 34px 10px; text-align: center;
    box-shadow: 0 6px 0 rgba(75,45,32,.55); min-width: 300px;
}
.welcome-badge .t { font-family: 'Itim', cursive; font-size: 2rem; color: #ffe9bd; line-height: 1.05; }
.welcome-badge .s { font-size: .9rem; color: #fbe3bd; }

/* Tab navigasi */
.st-key-nav { margin-top: 6px; }
.st-key-nav div[role="radiogroup"] {
    background: var(--cream); border: 3px dashed #cdbd98; border-bottom: 0;
    border-radius: 26px 26px 0 0; padding: 12px 22px 8px; gap: 22px; width: fit-content;
    max-width: 100%; flex-wrap: wrap; margin-bottom: -22px; position: relative; z-index: 2;
}
.st-key-nav div[role="radiogroup"] label {
    background: transparent !important; border: 0 !important; box-shadow: none !important;
    padding: 0 4px !important; border-radius: 0 !important;
}
.st-key-nav div[role="radiogroup"] label p {
    font-family: 'Itim', cursive; font-size: 1.45rem; color: var(--milk);
}
.st-key-nav div[role="radiogroup"] label:has(input:checked) p { color: var(--choc); }
.st-key-nav div[role="radiogroup"] label:has(input:checked) { border-bottom: 4px solid var(--leaf) !important; }

/* Radio pill umum */
div[role="radiogroup"] { gap: 8px; flex-wrap: wrap; }
div[role="radiogroup"] label {
    background: var(--butter); border: 2px solid var(--butter-edge);
    border-radius: 999px; padding: 2px 16px; margin: 0;
}
div[role="radiogroup"] label > div:first-child { display: none; }
div[role="radiogroup"] label p { color: var(--ink); margin: 0; }
div[role="radiogroup"] label:has(input:checked) { background: var(--choc); border-color: var(--choc-dark); }
div[role="radiogroup"] label:has(input:checked) p { color: #ffe9bd; }

/* Pita header */
.band {
    position: relative; margin-top: 0; margin-bottom: -1rem;
    background: repeating-linear-gradient(135deg, #6a4332 0 14px, #61402f 14px 28px);
    border: 4px solid #fffaf0; border-bottom: 0;
    border-radius: 26px 26px 0 0; padding: 20px 28px 22px; color: #ffe9bd;
    box-shadow: 0 0 0 3px #e8d9b4;
}
.band .ttl { font-family: 'Itim', cursive; font-size: 2.3rem; color: #fff6e0; line-height: 1.1; }
.band .sub { font-size: .92rem; color: #fbe3bd; margin: 2px 0 12px; max-width: 70%; }
.pills { display: flex; gap: 12px; flex-wrap: wrap; }
.pill {
    background: var(--cream); color: var(--ink); border: 3px solid var(--choc-dark);
    border-radius: 999px; padding: 3px 20px; font-size: .88rem; font-weight: 600;
    box-shadow: inset 0 -3px 0 rgba(176,138,91,.35);
}
.band .dot-circle {
    position: absolute; right: 26px; top: 18px; width: 98px; height: 98px;
    border-radius: 50%; border: 6px solid #fffaf0;
    background: radial-gradient(circle, #f2d7b8 22%, transparent 24%) 0 0/16px 16px, #ecc9a6;
    display: flex; align-items: center; justify-content: center; font-size: 2.4rem;
    box-shadow: 0 3px 0 rgba(0,0,0,.18);
}

/* Panel isi */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--cream); border: 4px solid #fffaf0 !important; border-top: 0 !important;
    border-radius: 0 0 26px 26px !important; padding: 18px 16px 14px !important;
    box-shadow: 0 0 0 3px #e8d9b4;
}
div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stVerticalBlockBorderWrapper"] {
    box-shadow: none;
}

/* Judul seksi */
.section-title {
    display: flex; align-items: center; gap: 10px; width: 100%;
    font-family: 'Itim', cursive; font-size: 1.55rem; color: var(--ink);
    border-bottom: 2px dashed #d8c89f; padding-bottom: 6px; margin: 14px 0 10px;
}
.section-title::before {
    content: "✿"; flex: 0 0 34px; height: 34px; border-radius: 50%;
    background: var(--leaf); color: #fff; display: inline-flex;
    align-items: center; justify-content: center; font-size: 1.05rem;
    box-shadow: 0 2px 0 var(--leaf-dark);
}

/* Kartu kunci */
.key-card {
    border-radius: 20px; padding: 14px 20px; color: #fff6e0; margin-bottom: 10px;
    border: 3px solid var(--choc-dark); box-shadow: 0 5px 0 rgba(75,45,32,.35);
}
.key-card .label { font-size: .85rem; opacity: .92; }
.key-card .value { font-family: 'Itim', cursive; font-size: 1.4rem; word-break: break-all; }
.k-pub { background: var(--leaf-dark); }
.k-prv { background: var(--choc); }

/* Kartu langkah / hasil */
.step, .result-box {
    background: var(--butter); color: var(--ink);
    border: 2px solid var(--butter-edge); border-radius: 22px 22px 22px 8px;
    padding: 12px 18px; margin: 12px 0; position: relative;
    box-shadow: 3px 4px 0 var(--butter-edge);
}
.step.s2 { background: #fbeec8; }
.step.s3 { background: #eef0c9; border-color: #c4cc84; box-shadow: 3px 4px 0 #c4cc84; }
.step.s4 { background: #fde6cf; border-color: #e1b58a; box-shadow: 3px 4px 0 #e1b58a; }
.step .st-title, .result-title {
    font-family: 'Itim', cursive; font-size: 1.15rem; color: var(--choc); margin-bottom: 4px;
}
.step .st-calc { font-family: 'Courier New', monospace; font-size: 1rem; word-break: break-all; }
.step .st-note { font-size: .88rem; opacity: .85; margin-top: 4px; }
.step .ok { color: var(--leaf-dark); font-weight: 700; }
.result-box { word-break: break-all; white-space: pre-wrap; background: #fffaf0; border-color: var(--milk); box-shadow: 3px 4px 0 var(--milk); }
.result-box.dec { background: #f1f4d6; border-color: var(--leaf); box-shadow: 3px 4px 0 var(--leaf); }
.result-box.dec .result-title { color: var(--leaf-dark); }

/* Tabel */
.tbl-wrap {
    max-height: 300px; overflow: auto; margin-top: 10px; border-radius: 16px;
    border: 3px solid var(--choc-dark); box-shadow: 0 4px 0 rgba(75,45,32,.25);
}
table.steps { width: 100%; border-collapse: collapse; background: var(--paper); }
table.steps th {
    background: var(--choc); color: #ffe9bd; padding: 8px 10px; position: sticky; top: 0;
    text-align: center; font-family: 'Itim', cursive; font-weight: 400; white-space: nowrap;
}
table.steps td {
    padding: 6px 10px; text-align: center; color: var(--ink);
    border-bottom: 1px dashed #dccfa6; font-family: 'Courier New', monospace;
}
table.steps tr:nth-child(even) td { background: #fbf0d3; }

/* Input */
div[data-baseweb="input"], div[data-baseweb="textarea"], div[data-baseweb="base-input"] {
    background: var(--paper) !important; border-radius: 16px !important;
}
div[data-baseweb="input"], div[data-baseweb="textarea"] { border: 2px solid var(--butter-edge) !important; }
div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea {
    color: var(--ink) !important; font-family: 'Mali', sans-serif;
}
.stApp label p { color: var(--ink); font-weight: 600; }
div[data-testid="stCaptionContainer"] p { color: #8a6a55; }

/* Tombol (juga download_button) */
div.stButton > button, div.stDownloadButton > button {
    background: var(--choc); color: #fff3d6; border: 3px solid var(--choc-dark);
    border-radius: 18px; padding: 8px 28px; font-family: 'Itim', cursive; font-size: 1.2rem;
    box-shadow: 0 5px 0 var(--choc-dark); transition: transform .12s, box-shadow .12s;
}
div.stButton > button:hover, div.stDownloadButton > button:hover {
    transform: translateY(-2px); box-shadow: 0 7px 0 var(--choc-dark);
    background: var(--milk); color: #fff; border-color: var(--choc-dark);
}
div.stButton > button:active, div.stDownloadButton > button:active {
    transform: translateY(3px); box-shadow: 0 2px 0 var(--choc-dark);
}

/* Expander & alert */
div[data-testid="stExpander"] details {
    background: var(--paper); border: 2px dashed var(--milk); border-radius: 18px;
}
div[data-testid="stExpander"] summary p { color: var(--choc); font-weight: 700; }
div[data-testid="stAlert"] { border-radius: 18px; }

/* Footer */
.footer-strip {
    margin-top: 6px; padding: 14px; text-align: center; color: #fff3d6; font-size: .95rem;
    background: repeating-linear-gradient(135deg, #6a4332 0 14px, #61402f 14px 28px);
    border: 4px solid #fffaf0; border-radius: 18px; box-shadow: 0 0 0 3px #e8d9b4;
}

/* Responsif */
@media (max-width: 640px) {
    :root { --pad: 12px; }
    .block-container, div[data-testid="stMainBlockContainer"] {
        margin: 10px auto; border-width: 6px; border-radius: 28px;
    }
    .awning { height: 60px; }
    .awning span { height: 54px; border-radius: 0 0 18px 18px; }
    .welcome-badge { min-width: 200px; top: -76px; padding: 8px 16px 6px; }
    .welcome-badge .t { font-size: 1.4rem; }
    .st-key-nav div[role="radiogroup"] { padding: 10px 14px 6px; gap: 10px; }
    .st-key-nav div[role="radiogroup"] label p { font-size: 1.15rem; }
    .band { padding: 16px 16px 18px; }
    .band .dot-circle { display: none; }
    .band .sub { max-width: 100%; }
    .band .ttl { font-size: 1.7rem; }
    .section-title { font-size: 1.3rem; }
    div[data-testid="stVerticalBlockBorderWrapper"] { padding: 12px 8px 10px !important; }
    div.stButton > button, div.stDownloadButton > button { width: 100%; }
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
    return f'<div class="tbl-wrap"><table class="steps"><tr>{head}</tr>{body}</table></div>'


def step_box(title, calc, note="", css=""):
    note_html = f'<div class="st-note">{note}</div>' if note else ""
    return (
        f'<div class="step {css}"><div class="st-title">{title}</div>'
        f'<div class="st-calc">{calc}</div>{note_html}</div>'
    )


def md(html):
    st.markdown(html, unsafe_allow_html=True)


def block_size_picker(n, key):
    """Pilihan ukuran blok (digit) yang valid untuk n."""
    sizes = valid_block_sizes(n)
    if key in st.session_state and st.session_state[key] not in sizes:
        del st.session_state[key]  # n berubah, pilihan lama tidak valid lagi
    k = st.radio(
        "Pesan dipisah menjadi blok berapa digit?",
        sizes,
        index=sizes.index(3) if 3 in sizes else 0,
        horizontal=True,
        format_func=lambda x: f"{x} digit",
        key=key,
    )
    st.caption(
        f"Nilai blok terbesar ({10 ** k - 1}) harus lebih kecil dari n, "
        f"jadi ukuran blok maksimal untuk n ini {sizes[-1]} digit. "
        "Ukuran blok yang sama harus dipakai saat enkripsi dan dekripsi."
    )
    return k


def render_key_generation(p, q, e_input, n, phi, e, d):
    """Semua langkah pembangkitan kunci (dipakai di dalam expander)."""
    md(step_box(
        "Langkah 1 - Pastikan p dan q bilangan prima",
        f"p = {p} &rarr; prima &nbsp;|&nbsp; q = {q} &rarr; prima",
        "Lolos uji keprimaan (pembagian bilangan kecil + Miller-Rabin) dan p &ne; q. "
        '<span class="ok">Valid</span>',
    ))
    md(step_box(
        "Langkah 2 - Hitung n",
        f"n = p &times; q = {p} &times; {q} = <b>{n}</b>",
        f'Syarat ASCII: n &gt; 127 &rarr; {n} &gt; 127 <span class="ok">Terpenuhi</span>',
        "s2",
    ))
    md(step_box(
        "Langkah 3 - Hitung &phi;(n)",
        f"&phi;(n) = (p &minus; 1) &times; (q &minus; 1) = {p - 1} &times; {q - 1} = <b>{phi}</b>",
        css="s3",
    ))
    tries = gcd_tries(e_input, phi)
    mode = "dimasukkan manual" if e_input else "dipilih otomatis (bilangan ganjil terkecil &gt; 1)"
    md(step_box(
        "Langkah 4 - Pilih e",
        f"Syarat: 1 &lt; e &lt; &phi;(n) dan FPB(e, &phi;(n)) = 1 &rarr; e = <b>{e}</b>",
        f"e {mode}.",
        "s4",
    ))
    md(table(
        ["e yang dicoba", f"FPB(e, {phi})", "Koprima?"],
        [(te, g, "Ya" if g == 1 else "Tidak") for te, g in tries],
    ))
    rows_eu, g, coef = euclid_steps(e, phi)
    md(step_box(
        "Langkah 5 - Hitung d (invers modular)",
        f"e &times; d &equiv; 1 (mod &phi;(n)) &rarr; {e} &times; d &equiv; 1 (mod {phi})",
        "Dihitung dengan algoritma Euclid yang diperluas. Kolom s adalah koefisien e; "
        f"FPB akhir = {g}, s terakhir sebelum sisa 0 = {coef}.",
    ))
    md(table(["Langkah", "q (hasil bagi)", "r (sisa)", "s"], rows_eu))
    md(step_box(
        "Hasil d",
        f"d = {coef} mod {phi} = <b>{d}</b>",
        f'Verifikasi: e &times; d mod &phi;(n) = {e} &times; {d} mod {phi} = '
        f'{(e * d) % phi} <span class="ok">Benar (harus 1)</span>',
        "s3",
    ))
    md(step_box(
        "Langkah 6 - Kunci yang dihasilkan",
        f"Kunci Publik (e, n) = <b>({e}, {n})</b><br>"
        f"Kunci Privat (d, n) = <b>({d}, {n})</b>",
        "Kunci publik dipakai untuk enkripsi, kunci privat untuk dekripsi.",
        "s2",
    ))


# ---------------- Callback ----------------
def send_to_decrypt():
    """Isi form dekripsi dari hasil enkripsi terakhir lalu pindah tab."""
    r = st.session_state["enc_result"]
    st.session_state["dec_d"] = str(r["d"])
    st.session_state["dec_n"] = str(r["n"])
    st.session_state["cipher"] = r["cipher_out"]
    st.session_state["dec_blok"] = r["k"]
    st.session_state["nav"] = "dekripsi"


# ---------------- Halaman Enkripsi ----------------
def render_enc_result(r):
    section("Pembangkitan Kunci")
    with st.expander("Klik untuk menampilkan / menyembunyikan langkah pembangkitan kunci"):
        render_key_generation(r["p"], r["q"], r["e_input"], r["n"], r["phi"], r["e"], r["d"])
    md(key_card("k-pub", "Kunci Publik (e, n)", f"({r['e']}, {r['n']})"))
    md(key_card("k-prv", "Kunci Privat (d, n) - simpan baik-baik", f"({r['d']}, {r['n']})"))

    section("Pemisahan Blok")
    k, pad = r["k"], r["pad"]
    kode_str = " ".join(f"{c:03d}" for c in r["codes"])
    blok_str = " | ".join(x[0] for x in r["rows"])
    note = f"Blok terakhir ditambah {pad} angka 0 di belakang agar genap {k} digit." if pad else ""
    md(step_box(
        f"Pemisahan blok ({k} digit)",
        f"Kode ASCII (3 digit): {kode_str}<br>"
        f"Digit disambung: {r['digits']}<br>"
        f"Dipisah per {k} digit: {blok_str}",
        note,
    ))
    with st.expander("Klik untuk menampilkan tabel perhitungan per blok"):
        md(table(
            ["Blok", "Nilai (m)", f"Cipher (m^{r['e']} mod {r['n']})"],
            list(r["rows"]),
        ))

    section("Hasil")
    md(result_box("Ciphertext", r["cipher_out"]))
    st.caption(
        f"Untuk dekripsi, gunakan kunci privat (d, n) = ({r['d']}, {r['n']}) "
        f"dan ukuran blok {k} digit."
    )
    c1, c2 = st.columns(2)
    c1.download_button("Unduh ciphertext", r["cipher_out"], file_name="ciphertext.txt")
    c2.button("Kirim ke Dekripsi", on_click=send_to_decrypt)


def page_enkripsi():
    st.session_state.setdefault("enc_p", "1009")
    st.session_state.setdefault("enc_q", "1013")
    st.session_state.setdefault("enc_e", "0")

    section("Input Enkripsi")
    col1, col2, col3 = st.columns(3)
    p_txt = col1.text_input("p (prima)", key="enc_p")
    q_txt = col2.text_input("q (prima)", key="enc_q")
    e_txt = col3.text_input("e (0 = otomatis)", key="enc_e")

    try:
        p = parse_int(p_txt, "p", 2)
        q = parse_int(q_txt, "q", 2)
        e_input = parse_int(e_txt, "e", 0)
        n, phi, e, d = generate_keys(p, q, e_input or None)
    except ValueError as ex:
        st.error(str(ex))
        return

    plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                         placeholder="Ketik pesan rahasiamu di sini...")
    k = block_size_picker(n, "enc_blok")
    params = (p, q, e_input, k, plain)

    if st.button("Enkripsi"):
        if not plain:
            st.warning("Isi plaintext dulu.")
        else:
            try:
                codes, digits, pad, rows = encrypt_blocks(plain, e, n, k)
            except ValueError as ex:
                st.error(str(ex))
            else:
                st.session_state["enc_result"] = dict(
                    params=params, p=p, q=q, e_input=e_input, n=n, phi=phi, e=e, d=d,
                    k=k, codes=codes, digits=digits, pad=pad, rows=rows,
                    cipher_out=" ".join(str(x[2]) for x in rows),
                )

    r = st.session_state.get("enc_result")
    if r:
        if r["params"] != params:
            st.info("Input sudah berubah sejak hasil ini dibuat. Tekan Enkripsi lagi untuk memperbarui.")
        render_enc_result(r)


# ---------------- Halaman Dekripsi ----------------
def render_dec_result(r):
    section("Perhitungan Setiap Blok")
    md(table(
        ["Cipher (c)", f"Nilai (c^{r['d']} mod {r['n']})", f"Blok ({r['k']} digit)"],
        r["rows"],
    ))
    section("Penyambungan Blok")
    codes, digits = r["codes"], r["digits"]
    kode_str = " ".join(f"{c:03d}" for c in codes)
    usable = len(codes) * 3
    note = f"{len(digits) - usable} digit pengisi di akhir dibuang." if len(digits) > usable else ""
    md(step_box(
        "Blok disambung lalu dibaca per 3 digit",
        f"Digit disambung: {digits}<br>Kode ASCII: {kode_str}",
        note,
        "s2",
    ))
    section("Hasil")
    md(result_box("Pesan asli (Plaintext)", r["plain"], "dec"))


def page_dekripsi():
    st.session_state.setdefault("dec_d", "")
    st.session_state.setdefault("dec_n", "")

    section("Input Dekripsi")
    col1, col2 = st.columns(2)
    d_txt = col1.text_input("d (kunci privat)", placeholder="mis. 816077", key="dec_d")
    n_txt = col2.text_input("n", placeholder="mis. 1022117", key="dec_n")
    cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                          placeholder="Tempel ciphertext di sini...")

    if not d_txt.strip() or not n_txt.strip():
        st.info("Isi d dan n terlebih dahulu.")
        return
    try:
        d = parse_int(d_txt, "d", 1)
        n = parse_int(n_txt, "n", 1)
    except ValueError as ex:
        st.error(str(ex))
        return
    if n <= 127:
        st.error("n harus lebih besar dari 127 untuk kode ASCII.")
        return

    k = block_size_picker(n, "dec_blok")
    params = (d, n, k, cipher)

    if st.button("Dekripsi"):
        if not cipher.strip():
            st.warning("Isi ciphertext dulu.")
        else:
            try:
                rows, digits, codes, plain_out = decrypt_blocks(cipher, d, n, k)
            except ValueError as ex:
                st.error(
                    f"{ex} Periksa juga bahwa kunci (d, n) dan ukuran blok sama "
                    "dengan saat enkripsi."
                )
            else:
                st.session_state["dec_result"] = dict(
                    params=params, d=d, n=n, k=k, rows=rows,
                    digits=digits, codes=codes, plain=plain_out,
                )

    r = st.session_state.get("dec_result")
    if r:
        if r["params"] != params:
            st.info("Input sudah berubah sejak hasil ini dibuat. Tekan Dekripsi lagi untuk memperbarui.")
        render_dec_result(r)


# ---------------- Halaman Tentang ----------------
def page_tentang():
    section("Cara kerja")
    md(step_box(
        "1. Pesan menjadi angka",
        "Tiap karakter diubah ke kode ASCII 3 digit, lalu semua digit disambung.",
    ))
    md(step_box(
        "2. Angka dipecah menjadi blok",
        "Digit dipotong per k digit. Nilai blok terbesar harus lebih kecil dari n.",
        css="s2",
    ))
    md(step_box(
        "3. Tiap blok dienkripsi",
        "c = m<sup>e</sup> mod n dengan kunci publik (e, n). "
        "Dekripsi memakai m = c<sup>d</sup> mod n dengan kunci privat (d, n).",
        css="s3",
    ))
    section("Tips")
    st.markdown(
        "- p dan q boleh bilangan besar (sampai ratusan digit); keprimaan diuji dengan Miller-Rabin.\n"
        "- Isi e dengan 0 agar dipilih otomatis.\n"
        "- Setelah enkripsi, tombol **Kirim ke Dekripsi** mengisi kunci dan ciphertext otomatis.\n"
        "- Ukuran blok harus sama saat enkripsi dan dekripsi."
    )
    st.caption("Untuk belajar saja. Jangan dipakai untuk mengamankan data sungguhan.")


# ---------------- Rangka halaman ----------------
PAGES = {
    "enkripsi": ("🔒 Enkripsi", "Enkripsi", "Ubah pesan jadi ciphertext dengan kunci publik."),
    "dekripsi": ("🔓 Dekripsi", "Dekripsi", "Kembalikan ciphertext jadi pesan dengan kunci privat."),
    "tentang": ("☕ Tentang", "Tentang", "Ringkasan cara kerja kalkulator ini."),
}

md(
    """
<div class="awning"><span></span><span></span><span></span><span></span>
<span></span><span></span><span></span><span></span></div>
<div class="welcome-wrap">
  <div class="welcome-badge">
    <div class="t">Selamat Datang!</div>
    <div class="s">Kalkulator RSA &#9834;(&acute;&nabla;&#96;)</div>
  </div>
</div>
"""
)

page = st.radio(
    "Menu",
    list(PAGES.keys()),
    horizontal=True,
    format_func=lambda x: PAGES[x][0],
    label_visibility="collapsed",
    key="nav",
)
_, page_name, page_sub = PAGES[page]

md(
    f"""
<div class="band">
  <div class="ttl">&epsilon; {page_name} &#1079;</div>
  <div class="sub">{page_sub} Kode ASCII, p dan q kamu tentukan sendiri.</div>
  <div class="pills">
    <span class="pill">status: OPEN</span>
    <span class="pill">mode: {page_name}</span>
  </div>
  <div class="dot-circle">🔐</div>
</div>
"""
)

with st.container(border=True):
    if page == "enkripsi":
        page_enkripsi()
    elif page == "dekripsi":
        page_dekripsi()
    else:
        page_tentang()

md('<div class="footer-strip">kalkulator RSA &middot; untuk belajar</div>')
