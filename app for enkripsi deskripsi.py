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
# Palet kafe: cokelat tua, cokelat susu, krim, kuning mentega, hijau daun
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
    --choc: #6a4332;        /* cokelat tua (frame, tombol) */
    --choc-dark: #4b2d20;   /* garis tepi */
    --milk: #b08a5b;        /* cokelat susu */
    --cream: #fdf4de;       /* krim panel */
    --butter: #f6e4b0;      /* kuning mentega (kartu) */
    --butter-edge: #d9b878;
    --leaf: #9bb05a;        /* hijau daun */
    --leaf-dark: #5f7330;   /* hijau daun lebih gelap (kontras lebih baik) */
    --paper: #fffaf0;
    --ink: #2e1a10;         /* teks gelap di atas latar terang (lebih pekat) */
    --white: #ffffff;       /* teks di atas latar cokelat/hijau */
}

/* ===== Latar halaman: kotak-kotak krim ===== */
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

/* ===== Frame cokelat bergaris ===== */
.block-container, div[data-testid="stMainBlockContainer"] {
    max-width: 800px;
    margin: 28px auto;
    padding: 0 26px 26px !important;
    background: repeating-linear-gradient(90deg, #6d4735 0 4px, #5f3d2d 4px 8px);
    border: 10px solid var(--choc-dark);
    border-radius: 42px;
    box-shadow: 0 0 0 4px #fdf4de, 0 14px 30px rgba(75,45,32,.35);
}
[data-testid="stMain"] { overflow-y: auto !important; }
.stApp h1, .stApp h2, .stApp h3, .stApp p, .stApp label, .stApp span, .stApp li {
    font-family: 'Mali', sans-serif;
}

/* ===== Kanopi + badge Welcome ===== */
.awning {
    display: flex; gap: 0; margin: 0 -26px; height: 78px; border-radius: 32px 32px 0 0; overflow: hidden;
    border-bottom: 6px solid var(--choc-dark);
    background: var(--choc-dark);
}
.awning span {
    flex: 1; height: 72px; border-radius: 0 0 30px 30px;
    border: 3px solid var(--choc-dark); border-top: 0;
}
.awning span:nth-child(odd)  { background: #fdebc8; }
.awning span:nth-child(even) { background: var(--leaf); }
.welcome-wrap { height: 0; position: relative; z-index: 5; }
.welcome-badge {
    position: absolute; left: 50%; top: -98px; transform: translateX(-50%);
    background: var(--choc); border: 4px solid var(--choc-dark);
    outline: 3px dashed #c9a27a; outline-offset: -11px;
    border-radius: 26px; padding: 14px 34px 12px; text-align: center;
    box-shadow: 0 6px 0 rgba(75,45,32,.55); min-width: 460px;
}
.welcome-badge .t {
    font-family: 'Itim', cursive; font-size: 2.2rem; color: #ffffff; line-height: 1.05;
    text-shadow: 0 2px 0 rgba(0,0,0,.35);
}
.welcome-badge .s {
    font-size: 1.05rem; color: #ffffff; font-weight: 700; margin-top: 2px;
    text-shadow: 0 1px 0 rgba(0,0,0,.35);
}

/* ===== Tab (st.tabs): kotak jelas, tulisan CREAM besar ===== */
div[data-baseweb="tab-list"] {
    background: transparent; border: 0; border-radius: 0;
    padding: 14px 0 0; gap: 16px; width: 100%; max-width: 100%;
    margin-top: 8px; flex-wrap: wrap;
}
html body button[role="tab"],
html body button[data-baseweb="tab"] {
    background: var(--choc-dark) !important;      /* kotak cokelat tua */
    border: 4px solid var(--cream) !important;    /* garis kotak cream */
    border-radius: 18px !important;
    padding: 8px 28px 10px !important; height: auto !important;
    opacity: 1 !important;
    box-shadow: 0 5px 0 rgba(0,0,0,.45);
    transition: background .12s, transform .12s;
}
html body button[role="tab"]:hover {
    background: var(--choc) !important; transform: translateY(-2px);
}
html body button[role="tab"] *,
html body button[data-baseweb="tab"] *,
html body button[role="tab"] p,
html body button[role="tab"] span,
html body button[role="tab"] div[data-testid="stMarkdownContainer"] p {
    font-family: 'Itim', cursive !important;
    font-size: 3rem !important;                    /* lebih besar */
    font-weight: 700 !important;
    color: #fdf4de !important; -webkit-text-fill-color: #fdf4de !important;
    line-height: 1.2 !important; margin: 0 !important; opacity: 1 !important;
    text-shadow: 0 2px 0 rgba(0,0,0,.5) !important;
}
/* tab yang sedang dipilih: kotak hijau + garis cream lebih tebal */
html body button[role="tab"][aria-selected="true"] {
    background: var(--leaf-dark) !important;
    border-color: #fffaf0 !important;
    border-width: 5px !important;
    box-shadow: 0 5px 0 #44541f;
}
/* hilangkan garis merah/abu-abu di bawah tab */
div[data-baseweb="tab-highlight"],
div[data-baseweb="tab-border"],
html body div[data-baseweb="tab-list"]::after { display: none !important; }
div[data-baseweb="tab-panel"] { padding-top: 0 !important; }

/* ===== Radio pill umum (pilihan blok) ===== */
div[role="radiogroup"] { gap: 8px; }
div[role="radiogroup"] label {
    background: var(--butter); border: 2px solid var(--butter-edge);
    border-radius: 999px; padding: 2px 16px; margin: 0;
}
div[role="radiogroup"] label > div:first-child { display: none; }
div[role="radiogroup"] label p { color: var(--ink) !important; margin: 0; font-weight: 700; }
div[role="radiogroup"] label:has(input:checked) {
    background: var(--choc); border-color: var(--choc-dark);
}
div[role="radiogroup"] label:has(input:checked) p { color: #fdf4de !important; }

/* ===== Pita header "home + about" ===== */
.band {
    position: relative; margin-top: 0; margin-bottom: -0.6rem;
    background: repeating-linear-gradient(135deg, #6a4332 0 14px, #61402f 14px 28px);
    border: 4px solid #fffaf0; border-bottom: 0;
    border-radius: 26px 26px 0 0; padding: 20px 28px 22px; color: #ffffff;
    box-shadow: 0 0 0 3px #e8d9b4;
}
.band .ttl {
    font-family: 'Itim', cursive; font-size: 2.3rem; color: #ffffff; line-height: 1.1;
    text-shadow: 0 2px 0 rgba(0,0,0,.3);
}
.band .sub { font-size: .98rem; color: #ffffff; font-weight: 600; margin: 2px 0 12px; max-width: 72%; }
.pills { display: flex; gap: 12px; flex-wrap: wrap; }
.pill {
    background: var(--cream); color: var(--ink); border: 3px solid var(--choc-dark);
    border-radius: 999px; padding: 3px 20px; font-size: .88rem; font-weight: 700;
    box-shadow: inset 0 -3px 0 rgba(176,138,91,.35);
}
.band .dot-circle {
    position: absolute; right: 26px; top: 18px; width: 98px; height: 98px;
    border-radius: 50%; border: 6px solid #fffaf0;
    background: radial-gradient(circle, #f2d7b8 22%, transparent 24%) 0 0/16px 16px, #ecc9a6;
    display: flex; align-items: center; justify-content: center; font-size: 2.4rem;
    box-shadow: 0 3px 0 rgba(0,0,0,.18);
}

/* ===== Panel isi (container border) ===== */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--cream); border: 4px solid #fffaf0 !important; border-top: 0 !important;
    border-radius: 0 0 26px 26px !important; padding: 18px 16px 14px !important;
    box-shadow: 0 0 0 3px #e8d9b4;
}
div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stVerticalBlockBorderWrapper"] {
    box-shadow: none;
}

/* ===== Judul seksi: lingkaran hijau + garis putus ===== */
.section-title {
    display: flex; align-items: center; gap: 10px; width: 100%;
    font-family: 'Itim', cursive; font-size: 1.75rem; color: #fdf4de;
    border-bottom: 2px dashed #e8d9b4; padding-bottom: 6px; margin: 14px 0 10px;
}
.section-title::before {
    content: "✿"; width: 34px; height: 34px; border-radius: 50%;
    background: var(--leaf-dark); color: #fff; display: inline-flex;
    align-items: center; justify-content: center; font-size: 1.05rem;
    box-shadow: 0 2px 0 #44541f;
}

/* ===== Kartu kunci ===== */
.key-card {
    border-radius: 20px; padding: 14px 20px; color: #ffffff; margin-bottom: 10px;
    border: 3px solid var(--choc-dark); box-shadow: 0 5px 0 rgba(75,45,32,.35);
}
.key-card .label { font-size: .9rem; color: #ffffff; font-weight: 600; }
.key-card .value { font-family: 'Itim', cursive; font-size: 1.5rem; color: #ffffff; word-break: break-all; }
.k-pub { background: var(--leaf-dark); }
.k-prv { background: var(--choc); }

/* ===== Kartu langkah / hasil (gaya balon kuning) ===== */
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
    font-family: 'Itim', cursive; font-size: 1.2rem; color: var(--choc-dark); margin-bottom: 4px;
}
.step .st-calc { font-family: 'Courier New', monospace; font-size: 1rem; font-weight: 700; word-break: break-all; }
.step .st-note { font-size: .9rem; opacity: 1; margin-top: 4px; }
.step .ok { color: var(--leaf-dark); font-weight: 700; }
.result-box { word-break: break-all; background: #fffaf0; border-color: var(--milk); box-shadow: 3px 4px 0 var(--milk); font-weight: 600; }
.result-box.dec { background: #f1f4d6; border-color: var(--leaf); box-shadow: 3px 4px 0 var(--leaf); }
.result-box.dec .result-title { color: var(--leaf-dark); }

/* ===== Tabel ===== */
.tbl-wrap {
    max-height: 300px; overflow-y: auto; margin-top: 10px; border-radius: 16px;
    border: 3px solid var(--choc-dark); box-shadow: 0 4px 0 rgba(75,45,32,.25);
}
table.steps { width: 100%; border-collapse: collapse; background: var(--paper); }
table.steps th {
    background: var(--choc); color: #ffffff; padding: 8px 10px; position: sticky; top: 0;
    text-align: center; font-family: 'Itim', cursive; font-weight: 400;
}
table.steps td {
    padding: 6px 10px; text-align: center; color: var(--ink);
    border-bottom: 1px dashed #c9bb8c; font-family: 'Courier New', monospace; font-weight: 700;
}
table.steps tr:nth-child(even) td { background: #fbf0d3; }

/* ===== Input ===== */
div[data-baseweb="input"], div[data-baseweb="textarea"], div[data-baseweb="base-input"] {
    background: var(--paper) !important; border-radius: 16px !important;
}
div[data-baseweb="input"], div[data-baseweb="textarea"] {
    border: 2px solid var(--milk) !important;
}
div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea {
    color: var(--ink) !important; font-family: 'Mali', sans-serif; font-weight: 600;
}
div[data-testid="stNumberInput"] button { color: var(--choc) !important; background: transparent !important; }
[data-testid="stWidgetLabel"],
[data-testid="stWidgetLabel"] *,
[data-testid="stWidgetLabel"] label p { color: #fdf4de !important; font-weight: 700; }
div[data-testid="stCaptionContainer"],
div[data-testid="stCaptionContainer"] *,
div[data-testid="stCaptionContainer"] p { color: #fdf4de !important; font-weight: 600; }

/* ===== Tombol ala "Button" cokelat ===== */
div.stButton > button {
    background: var(--choc); color: #ffffff; border: 3px solid var(--choc-dark);
    border-radius: 18px; padding: 8px 34px; font-family: 'Itim', cursive; font-size: 1.3rem;
    box-shadow: 0 5px 0 var(--choc-dark); transition: transform .12s, box-shadow .12s;
}
div.stButton > button p { color: #ffffff !important; }
div.stButton > button:hover {
    transform: translateY(-2px); box-shadow: 0 7px 0 var(--choc-dark);
    background: var(--milk); color: #fff; border-color: var(--choc-dark);
}
div.stButton > button:active { transform: translateY(3px); box-shadow: 0 2px 0 var(--choc-dark); }

/* ===== Expander ===== */
div[data-testid="stExpander"] details {
    background: var(--paper); border: 2px dashed var(--milk); border-radius: 18px;
}
div[data-testid="stExpander"] summary p { color: var(--choc-dark); font-weight: 700; }

/* ===== Alert ===== */
div[data-testid="stAlert"] { border-radius: 18px; }

/* ===== Footer strip ===== */
.footer-strip {
    margin-top: 6px; padding: 14px; text-align: center; color: #ffffff; font-size: 1rem; font-weight: 600;
    background: repeating-linear-gradient(135deg, #6a4332 0 14px, #61402f 14px 28px);
    border: 4px solid #fffaf0; border-radius: 18px; box-shadow: 0 0 0 3px #e8d9b4;
}

@media (max-width: 640px) {
    .welcome-badge { min-width: 270px; padding: 10px 16px 8px; top: -92px; }
    .welcome-badge .t { font-size: 1.6rem; }
    .welcome-badge .s { font-size: .85rem; }
    html body button[role="tab"] *, html body button[role="tab"] p { font-size: 1.8rem !important; }
    html body button[role="tab"] { padding: 4px 14px 8px !important; }
    div[data-baseweb="tab-list"] { gap: 8px; padding: 10px 0 0; }
    .band .dot-circle { display: none; }
    .band .sub { max-width: 100%; }
    .band .ttl { font-size: 1.8rem; }
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
    if st.session_state.get(key) not in sizes:
        st.session_state[key] = 3 if 3 in sizes else sizes[0]
    k = st.radio(
        "Pesan dipisah menjadi blok berapa digit?",
        sizes,
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


# ---------------- Tampilan hasil (disimpan di session_state) ----------------
def render_enc_result(r):
    """Tampilkan hasil enkripsi yang tersimpan (tidak hilang saat pindah tab)."""
    section("Pembangkitan Kunci")
    with st.expander("Klik untuk menampilkan / menyembunyikan langkah pembangkitan kunci"):
        render_key_generation(r["p"], r["q"], r["e_input"], r["n"], r["phi"], r["e"], r["d"])
    st.markdown(
        key_card("k-pub", "Kunci Publik (e, n)", f"({r['e']}, {r['n']})")
        + key_card("k-prv", "Kunci Privat (d, n)", f"({r['d']}, {r['n']})"),
        unsafe_allow_html=True,
    )

    section("Pemisahan Blok")
    k, rows, pad = r["k"], r["rows"], r["pad"]
    kode_str = " ".join(f"{c:03d}" for c in r["codes"])
    blok_str = " | ".join(x[0] for x in rows)
    note = f"Blok terakhir ditambah {pad} angka 0 di belakang agar genap {k} digit." if pad else ""
    st.markdown(
        step_box(
            f"Pemisahan blok ({k} digit)",
            f"Kode ASCII (3 digit): {kode_str}<br>"
            f"Digit disambung: {r['digits']}<br>"
            f"Dipisah per {k} digit: {blok_str}",
            note,
        ),
        unsafe_allow_html=True,
    )
    with st.expander("Klik untuk menampilkan tabel perhitungan per blok"):
        st.markdown(
            table(["Blok", "Nilai (m)", f"Cipher (m^{r['e']} mod {r['n']})"],
                  [(b, m, c) for b, m, c in rows]),
            unsafe_allow_html=True,
        )

    section("Hasil")
    st.markdown(result_box("Ciphertext", r["cipher_out"]), unsafe_allow_html=True)
    st.caption(
        f"Untuk dekripsi, gunakan kunci privat (d, n) = ({r['d']}, {r['n']}) "
        f"dan ukuran blok {k} digit."
    )


def render_dec_result(r):
    """Tampilkan hasil dekripsi yang tersimpan."""
    if "error" in r:
        st.error(r["error"])
        return
    k, n, d = r["k"], r["n"], r["d"]
    section("Perhitungan Setiap Blok")
    st.markdown(
        table(["Cipher (c)", f"Nilai (c^{d} mod {n})", f"Blok ({k} digit)"], r["rows"]),
        unsafe_allow_html=True,
    )
    section("Penyambungan Blok")
    codes, digits = r["codes"], r["digits"]
    kode_str = " ".join(f"{c:03d}" for c in codes)
    usable = len(codes) * 3
    note = f"{len(digits) - usable} digit pengisi di akhir dibuang." if len(digits) > usable else ""
    st.markdown(
        step_box(
            "Blok disambung lalu dibaca per 3 digit",
            f"Digit disambung: {digits}<br>Kode ASCII: {kode_str}",
            note,
            "s2",
        ),
        unsafe_allow_html=True,
    )
    section("Hasil")
    st.markdown(result_box("Pesan asli (Plaintext)", r["plain_out"], "dec"), unsafe_allow_html=True)

    enc = st.session_state.get("enc_result")
    if enc and enc["cipher_out"].split() == r["cipher_in"].split():
        cocok = enc["plain"] == r["plain_out"]
        st.markdown(
            step_box(
                "Perbandingan dengan plaintext saat enkripsi",
                f"Plaintext enkripsi: {esc(enc['plain'])}<br>Hasil dekripsi: {esc(r['plain_out'])}",
                f'<span class="ok">{"Sama persis" if cocok else "Berbeda"}</span>',
                "s3",
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

    keys_ok = True
    try:
        n, phi, e, d = generate_keys(p, q, e_input or None)
    except ValueError as ex:
        st.error(str(ex))
        keys_ok = False

    plain = st.text_area("Plaintext (karakter ASCII)", height=120, key="plain",
                         placeholder="Ketik pesan rahasiamu di sini...")

    if keys_ok:
        k = block_size_picker(n, "enc_blok")
        if st.button("Enkripsi", key="btn_enc"):
            if not plain:
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    codes, digits, pad, rows = encrypt_blocks(plain, e, n, k)
                    st.session_state["enc_result"] = {
                        "p": p, "q": q, "e_input": e_input, "n": n, "phi": phi,
                        "e": e, "d": d, "k": k, "plain": plain,
                        "codes": codes, "digits": digits, "pad": pad, "rows": rows,
                        "cipher_out": " ".join(str(x[2]) for x in rows),
                    }
                except ValueError as ex:
                    st.error(str(ex))

    if st.session_state.get("enc_result"):
        render_enc_result(st.session_state["enc_result"])


# ---------------- Halaman Dekripsi ----------------
def use_last_encryption():
    r = st.session_state.get("enc_result")
    if not r:
        return
    st.session_state["dec_d"] = r["d"]
    st.session_state["dec_n"] = r["n"]
    st.session_state["cipher"] = r["cipher_out"]
    st.session_state["dec_blok"] = r["k"]


def page_dekripsi():
    enc = st.session_state.get("enc_result")
    if enc:
        section("Hasil Enkripsi Terakhir (pembanding)")
        st.markdown(
            result_box(
                "Ciphertext",
                f"{enc['cipher_out']}\n\nPlaintext asal: {enc['plain']}",
            )
            + key_card("k-prv", "Kunci Privat (d, n) dan ukuran blok",
                       f"({enc['d']}, {enc['n']}) &middot; blok {enc['k']} digit"),
            unsafe_allow_html=True,
        )
        st.button("Pakai data ini untuk dekripsi", key="btn_use", on_click=use_last_encryption)

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
    elif int(n) <= 127:
        st.error("n harus lebih besar dari 127 untuk kode ASCII.")
    else:
        d, n = int(d), int(n)
        k = block_size_picker(n, "dec_blok")
        if st.button("Dekripsi", key="btn_dec"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    rows, digits, codes, plain_out = decrypt_blocks(cipher, d, n, k)
                    st.session_state["dec_result"] = {
                        "d": d, "n": n, "k": k, "rows": rows, "digits": digits,
                        "codes": codes, "plain_out": plain_out, "cipher_in": cipher,
                    }
                except (ValueError, OverflowError):
                    st.session_state["dec_result"] = {
                        "error": "Ciphertext tidak valid, atau kunci (d, n) dan ukuran blok "
                                 "tidak cocok dengan saat enkripsi."
                    }

    if st.session_state.get("dec_result"):
        render_dec_result(st.session_state["dec_result"])


# ---------------- Halaman Tentang ----------------
def page_tentang():
    section("Cara kerja")
    st.markdown(
        step_box("1. Pesan menjadi angka",
                 "Tiap karakter diubah ke kode ASCII 3 digit, lalu semua digit disambung."),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("2. Angka dipecah menjadi blok",
                 "Digit dipotong per k digit. Nilai blok terbesar harus lebih kecil dari n.", css="s2"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("3. Tiap blok dienkripsi",
                 "c = m<sup>e</sup> mod n dengan kunci publik (e, n). "
                 "Dekripsi memakai m = c<sup>d</sup> mod n dengan kunci privat (d, n).", css="s3"),
        unsafe_allow_html=True,
    )
    section("Kelompok")
    st.markdown(
        step_box("Anggota", "Jovani (009)<br>Wafiq (028)<br>Naura (037)", css="s4"),
        unsafe_allow_html=True,
    )
    st.caption("Untuk belajar saja. Jangan dipakai untuk mengamankan data sungguhan.")


# ---------------- Rangka halaman ----------------
BAND_HTML = """
<div class="band">
  <div class="ttl">&epsilon; Kalkulator RSA &#1079;</div>
  <div class="sub">Enkripsi dan dekripsi pesan dengan kode ASCII. p dan q kamu tentukan sendiri.</div>
  <div class="pills">
    <span class="pill">status: OPEN</span>
    <span class="pill">Jovani (009)</span>
    <span class="pill">Wafiq (028)</span>
    <span class="pill">Naura (037)</span>
  </div>
  <div class="dot-circle">🔐</div>
</div>
"""

st.markdown(
    """
<div class="awning"><span></span><span></span><span></span><span></span>
<span></span><span></span><span></span><span></span></div>
<div class="welcome-wrap">
  <div class="welcome-badge">
    <div class="t">Selamat Datang!</div>
    <div class="s">Kalkulator RSA Jova, Ais, dan Naura &#9834;(&acute;&nabla;&#96;)</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

tab_enc, tab_dec, tab_info = st.tabs(["👤 Enkripsi", "ℹ️ Dekripsi", "☰ Tentang"])

with tab_enc:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_enkripsi()

with tab_dec:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_dekripsi()

with tab_info:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_tentang()
