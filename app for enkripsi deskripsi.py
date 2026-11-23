"""
Kalkulator RSA (input p dan q manual) - versi Streamlit, alfabet 26 huruf
Tampilan: kartu kafe ala "carrd" (cokelat bergaris, kanopi, tab, pita header).
Memakai 26 huruf: A=01, B=02, ..., Z=26 (tiap huruf ditulis 2 digit).
Kode huruf disambung, lalu dipisah menjadi blok k digit
(k bisa dipilih: 2, 3, dst.) dan tiap blok diproses dengan RSA.
Ada juga fitur Tanda Tangan Digital: hash SHA-256 pesan, lalu ditandatangani dengan
kunci privat RSA dan diverifikasi dengan kunci publik.
Jalankan lokal: streamlit run app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
import hashlib
from math import gcd, isqrt

import streamlit as st

MAX_CODE = 26  # A=1 ... Z=26


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
    if n <= MAX_CODE:
        raise ValueError(
            f"n = {n} terlalu kecil. Untuk huruf A-Z (kode 01-26) butuh n > {MAX_CODE}, "
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


def max_block_value(k):
    """
    Nilai blok terbesar yang mungkin muncul untuk blok k digit.
    k genap: blok pas dengan pasangan huruf -> paling besar 2626...26.
    k ganjil: blok bisa dimulai di tengah pasangan -> paling besar 9 lalu 2626...26
    (mis. k = 3 -> 926).
    """
    pairs = "26" * (k // 2)
    return int(pairs) if k % 2 == 0 else int("9" + pairs)


def valid_block_sizes(n, max_k=8):
    """Ukuran blok k (digit) yang valid: nilai blok terbesar harus < n."""
    return [k for k in range(2, max_k + 1) if max_block_value(k) < n]


def clean_text(text):
    """Buang spasi/baris baru, ubah ke huruf besar, pastikan hanya A-Z."""
    cleaned = "".join(text.split()).upper()
    for ch in cleaned:
        if not ("A" <= ch <= "Z"):
            raise ValueError(
                f"Karakter '{ch}' tidak valid. Hanya huruf A-Z yang boleh dipakai "
                "(spasi diabaikan, huruf kecil otomatis jadi besar)."
            )
    return cleaned


def encrypt_blocks(text, e, n, k):
    """
    Tiap huruf -> kode 2 digit (A=01..Z=26), disambung, dipisah per k digit,
    tiap blok dienkripsi. Return (letters, codes, digits, pad, rows),
    rows = list of (blok_str, m, cipher).
    """
    letters = clean_text(text)
    if not letters:
        raise ValueError("Plaintext tidak berisi huruf A-Z.")
    codes = [ord(ch) - 64 for ch in letters]
    digits = "".join(f"{c:02d}" for c in codes)
    pad = (-len(digits)) % k
    padded = digits + "0" * pad
    rows = []
    for i in range(0, len(padded), k):
        blok = padded[i:i + k]
        m = int(blok)
        rows.append((blok, m, pow(m, e, n)))
    return letters, codes, digits, pad, rows


def decrypt_blocks(cipher, d, n, k):
    """
    Dekripsi tiap blok, isi nol di kiri sampai k digit, sambung,
    lalu baca per 2 digit sebagai kode huruf (01-26).
    Return (rows, digits, codes, plaintext), rows = list of (c, m, blok_str).
    """
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
    codes = [int(digits[i:i + 2]) for i in range(0, len(digits) // 2 * 2, 2)]  # sisa <2 digit = pengisi
    while codes and codes[-1] == 0:                # buang kode 00 pengisi
        codes.pop()
    if any(c < 1 or c > MAX_CODE for c in codes):
        raise ValueError("Hasil bukan kode huruf 01-26, kunci atau ukuran blok tidak cocok.")
    plain = "".join(chr(c + 64) for c in codes)
    return rows, digits, codes, plain


def hash_mod(msg, n):
    """Hash SHA-256 pesan, lalu direduksi mod n agar bisa dipakai di RSA kecil."""
    digest = hashlib.sha256(msg.encode("utf-8")).hexdigest()
    return digest, int(digest, 16) % n


def sign_message(msg, d, n):
    """Tanda tangan: s = h^d mod n (h = hash pesan mod n). Pakai kunci privat."""
    digest, h = hash_mod(msg, n)
    return digest, h, pow(h, d, n)


def verify_signature(msg, sgn, e, n):
    """Verifikasi: v = s^e mod n harus sama dengan h = hash pesan mod n."""
    digest, h = hash_mod(msg, n)
    v = pow(sgn, e, n)
    return digest, h, v, v == h


# ---------------- Tampilan ----------------
# Palet kafe: cokelat tua, cokelat susu, krim, kuning mentega, hijau daun
st.set_page_config(
    page_title="Kalkulator RSA 26 Huruf",
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
.stApp h1, .stApp h2, .stApp h3, .stApp p, .stApp label, .stApp li {
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

/* ===== Tab (st.tabs): kotak jelas, tulisan CREAM besar =====
   Selector dibuat selengkap mungkin agar cocok di semua versi Streamlit. */
[data-testid="stTabs"] [role="tablist"],
.stTabs [role="tablist"],
div[data-baseweb="tab-list"] {
    background: transparent !important; border: 0 !important; border-bottom: 0 !important;
    box-shadow: none !important; border-radius: 0 !important;
    padding: 12px 0 6px !important; gap: 12px !important; width: 100% !important;
    max-width: 100% !important; margin-top: 8px !important; flex-wrap: wrap !important;
}
html body [data-testid="stTabs"] button,
html body .stTabs button,
html body [data-testid="stTab"],
html body button[role="tab"],
html body [role="tab"],
html body button[data-baseweb="tab"] {
    background: #4b2d20 !important;               /* kotak cokelat tua */
    background-color: #4b2d20 !important;
    border: 4px solid #fdf4de !important;         /* garis kotak cream */
    border-radius: 18px !important;
    padding: 6px 20px 8px !important; height: auto !important; min-height: 0 !important;
    opacity: 1 !important;
    box-shadow: 0 5px 0 rgba(0,0,0,.45) !important;
    transition: background .12s, transform .12s;
}
html body [data-testid="stTabs"] button:hover,
html body .stTabs button:hover,
html body button[role="tab"]:hover,
html body [role="tab"]:hover {
    background: #6a4332 !important; background-color: #6a4332 !important;
    transform: translateY(-2px);
}
html body [data-testid="stTabs"] button *,
html body .stTabs button *,
html body [data-testid="stTab"] *,
html body button[role="tab"] *,
html body [role="tab"] *,
html body button[data-baseweb="tab"] *,
html body [data-testid="stTabs"] button p,
html body .stTabs button p,
html body button[role="tab"] p,
html body button[role="tab"] span,
html body button[role="tab"] div[data-testid="stMarkdownContainer"] p {
    font-family: 'Itim', cursive !important;
    font-size: 1.7rem !important;                  /* ukuran tab */
    font-weight: 700 !important;
    color: #fdf4de !important; -webkit-text-fill-color: #fdf4de !important;
    line-height: 1.2 !important; margin: 0 !important; opacity: 1 !important;
    text-shadow: 0 2px 0 rgba(0,0,0,.5) !important;
}
/* tab yang sedang dipilih: kotak hijau + garis cream lebih tebal */
html body [data-testid="stTabs"] button[aria-selected="true"],
html body .stTabs button[aria-selected="true"],
html body [data-testid="stTab"][aria-selected="true"],
html body button[role="tab"][aria-selected="true"],
html body [role="tab"][aria-selected="true"] {
    background: #5f7330 !important; background-color: #5f7330 !important;
    border-color: #fffaf0 !important;
    border-width: 5px !important;
    box-shadow: 0 5px 0 #44541f !important;
}
html body [data-testid="stTabs"] button[aria-selected="true"] *,
html body .stTabs button[aria-selected="true"] *,
html body button[role="tab"][aria-selected="true"] *,
html body [role="tab"][aria-selected="true"] * {
    color: #fdf4de !important; -webkit-text-fill-color: #fdf4de !important;
}
/* hilangkan garis merah/abu-abu di bawah tab */
div[data-baseweb="tab-highlight"],
div[data-baseweb="tab-border"],
[data-testid="stTabs"] [role="tablist"]::after,
[data-testid="stTabs"] [role="tablist"]::before,
.stTabs [role="tablist"]::after,
.stTabs [role="tablist"]::before,
div[data-baseweb="tab-list"]::after,
div[data-baseweb="tab-list"]::before { display: none !important; content: none !important; }
[data-testid="stTabs"] > div:first-child,
.stTabs > div:first-child { border-bottom: 0 !important; box-shadow: none !important; }
div[data-baseweb="tab-panel"],
[data-testid="stTabs"] [role="tabpanel"],
.stTabs [role="tabpanel"] { padding-top: 0 !important; }

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

.result-box.good { background: #f1f4d6; border-color: var(--leaf); box-shadow: 3px 4px 0 var(--leaf); }
.result-box.good .result-title { color: var(--leaf-dark); }
.result-box.bad { background: #fde0d6; border-color: #c4623f; box-shadow: 3px 4px 0 #c4623f; }
.result-box.bad .result-title { color: #9a2f12; }

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
    background: var(--paper);
    border: 2px dashed var(--milk);
    border-radius: 18px;
}
div[data-testid="stExpander"] summary {
    display: flex !important;
    align-items: center !important;
    gap: 10px !important;
    padding: 12px 18px !important;
}
div[data-testid="stExpander"] summary p {
    color: var(--choc-dark);
    font-weight: 700;
    line-height: 1.4 !important;
    margin: 0 !important;
}
/* Jangan timpa font ikon bawaan Streamlit dengan font teks Mali */
div[data-testid="stExpander"] [data-testid="stIconMaterial"] {
    font-family: "Material Symbols Rounded" !important;
    font-weight: normal !important;
    font-style: normal !important;
    font-size: 24px !important;
    line-height: 1 !important;
    letter-spacing: normal !important;
    text-transform: none !important;
    white-space: nowrap !important;
    direction: ltr !important;
}

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
    html body [data-testid="stTabs"] button *, html body .stTabs button *,
    html body button[role="tab"] *, html body [role="tab"] * { font-size: 1.2rem !important; }
    html body [data-testid="stTabs"] button, html body .stTabs button,
    html body button[role="tab"], html body [role="tab"] { padding: 4px 10px 6px !important; }
    [data-testid="stTabs"] [role="tablist"], .stTabs [role="tablist"],
    div[data-baseweb="tab-list"] { gap: 8px !important; padding: 10px 0 0 !important; }
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
    # baris baru diubah menjadi <br> agar tidak menempel jadi satu baris
    return (
        f'<div class="result-box {css}"><div class="result-title">{title}</div>'
        f'{esc(text).replace(chr(10), "<br>")}</div>'
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
        st.session_state[key] = 4 if 4 in sizes else sizes[0]
    k = st.radio(
        "Pesan dipisah menjadi blok berapa digit?",
        sizes,
        horizontal=True,
        format_func=lambda x: f"{x} digit",
        key=key,
    )
    st.caption(
        f"Nilai tiap blok harus lebih kecil dari n = {n}. Blok k digit bisa bernilai sampai "
        f"{max_block_value(sizes[-1])} (untuk k = {sizes[-1]}), jadi ukuran blok maksimal {sizes[-1]} digit. "
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
            f'Syarat huruf A-Z (kode 01-26): n &gt; {MAX_CODE} &rarr; {n} &gt; {MAX_CODE} '
            '<span class="ok">Terpenuhi</span>',
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
    with st.expander("Tampilkan / sembunyikan langkah pembangkitan kunci"):
        render_key_generation(r["p"], r["q"], r["e_input"], r["n"], r["phi"], r["e"], r["d"])
    st.markdown(
        key_card("k-pub", "Kunci Publik (e, n)", f"({r['e']}, {r['n']})")
        + key_card("k-prv", "Kunci Privat (d, n)", f"({r['d']}, {r['n']})"),
        unsafe_allow_html=True,
    )

    section("Pemisahan Blok")
    k, rows, pad = r["k"], r["rows"], r["pad"]
    huruf_kode = " ".join(f"{ch}={c:02d}" for ch, c in zip(r["letters"], r["codes"]))
    blok_str = " | ".join(x[0] for x in rows)
    note = f"Blok terakhir ditambah {pad} angka 0 di belakang agar genap {k} digit." if pad else ""
    st.markdown(
        step_box(
            f"Pemisahan blok ({k} digit)",
            f"Huruf &rarr; kode (A=01 ... Z=26): {huruf_kode}<br>"
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
    kode_str = " ".join(f"{c:02d}" for c in codes)
    huruf_str = " ".join(chr(c + 64) for c in codes)
    usable = len(codes) * 2
    note = f"{len(digits) - usable} digit pengisi di akhir dibuang." if len(digits) > usable else ""
    st.markdown(
        step_box(
            "Blok disambung lalu dibaca per 2 digit",
            f"Digit disambung: {digits}<br>Kode huruf: {kode_str}<br>Huruf: {huruf_str}",
            note,
            "s2",
        ),
        unsafe_allow_html=True,
    )
    section("Hasil")
    st.markdown(result_box("Pesan asli (Plaintext)", r["plain_out"], "dec"), unsafe_allow_html=True)


# ---------------- Halaman Enkripsi ----------------
def page_enkripsi():
    section("Input Enkripsi")
    col1, col2, col3 = st.columns(3)
    # batas atas mencegah aplikasi hang (trial division) dan menjaga n tetap aman
    p = int(col1.number_input("p (prima)", min_value=2, max_value=10**7, value=1009,
                              step=1, key="enc_p"))
    q = int(col2.number_input("q (prima)", min_value=2, max_value=10**7, value=1013,
                              step=1, key="enc_q"))
    e_input = int(col3.number_input("e (0 = otomatis)", min_value=0, max_value=10**14,
                                    value=0, step=1, key="enc_e"))

    keys_ok = True
    k = None
    try:
        n, phi, e, d = generate_keys(p, q, e_input or None)
    except ValueError as ex:
        st.error(str(ex))
        keys_ok = False

    plain = st.text_area("Plaintext (huruf A-Z saja, spasi diabaikan)", height=120, key="plain",
                         placeholder="Ketik pesan rahasiamu di sini...")

    if keys_ok:
        k = block_size_picker(n, "enc_blok")
        if st.button("Enkripsi", key="btn_enc"):
            if not plain.strip():
                st.warning("Isi plaintext dulu.")
            else:
                try:
                    letters, codes, digits, pad, rows = encrypt_blocks(plain, e, n, k)
                    st.session_state["enc_result"] = {
                        "p": p, "q": q, "e_input": e_input, "n": n, "phi": phi,
                        "e": e, "d": d, "k": k, "plain": plain, "letters": letters,
                        "codes": codes, "digits": digits, "pad": pad, "rows": rows,
                        "cipher_out": " ".join(str(x[2]) for x in rows),
                        "sig": (p, q, e_input, plain, k),
                    }
                except ValueError as ex:
                    st.error(str(ex))

    r = st.session_state.get("enc_result")
    if r:
        cur = (p, q, e_input, plain, k) if keys_ok else None
        if cur != r.get("sig"):
            st.warning("Hasil di bawah berasal dari input sebelumnya. "
                       "Tekan Enkripsi lagi untuk memperbarui.")
        render_enc_result(r)


# ---------------- Halaman Dekripsi ----------------
def page_dekripsi():
    section("Input Dekripsi")
    col1, col2 = st.columns(2)
    d = col1.number_input("d (kunci privat)", min_value=1, max_value=10**15, value=None,
                          step=1, placeholder="mis. 816077", key="dec_d")
    n = col2.number_input("n", min_value=1, max_value=10**15, value=None,
                          step=1, placeholder="mis. 1022117", key="dec_n")

    cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                          placeholder="Tempel ciphertext di sini...")

    cur_sig = None
    if d is None or n is None:
        st.info("Isi d dan n terlebih dahulu.")
    elif int(n) <= MAX_CODE:
        st.error(f"n harus lebih besar dari {MAX_CODE} untuk huruf A-Z.")
    else:
        d, n = int(d), int(n)
        k = block_size_picker(n, "dec_blok")
        cur_sig = (d, n, k, cipher)
        if st.button("Dekripsi", key="btn_dec"):
            if not cipher.strip():
                st.warning("Isi ciphertext dulu.")
            else:
                try:
                    rows, digits, codes, plain_out = decrypt_blocks(cipher, d, n, k)
                    st.session_state["dec_result"] = {
                        "d": d, "n": n, "k": k, "rows": rows, "digits": digits,
                        "codes": codes, "plain_out": plain_out, "cipher_in": cipher,
                        "sig": cur_sig,
                    }
                except (ValueError, OverflowError):
                    st.session_state["dec_result"] = {
                        "error": "Ciphertext tidak valid, atau kunci (d, n) dan ukuran blok "
                                 "tidak cocok dengan saat enkripsi.",
                        "sig": cur_sig,
                    }

    r = st.session_state.get("dec_result")
    if r:
        if cur_sig != r.get("sig"):
            st.warning("Hasil di bawah berasal dari input sebelumnya. "
                       "Tekan Dekripsi lagi untuk memperbarui.")
        render_dec_result(r)


# ---------------- Tanda Tangan Digital ----------------
def render_sig_result(r):
    """Hasil pembuatan tanda tangan (tersimpan di session_state)."""
    section("Pembangkitan Kunci")
    with st.expander("Tampilkan / sembunyikan langkah pembangkitan kunci"):
        render_key_generation(r["p"], r["q"], r["e_input"], r["n"], r["phi"], r["e"], r["d"])
    st.markdown(
        key_card("k-pub", "Kunci Publik (e, n) - dibagikan untuk verifikasi", f"({r['e']}, {r['n']})")
        + key_card("k-prv", "Kunci Privat (d, n) - dirahasiakan, dipakai menandatangani",
                   f"({r['d']}, {r['n']})"),
        unsafe_allow_html=True,
    )
    section("Proses Tanda Tangan")
    st.markdown(
        step_box("Langkah 1 - Hash pesan dengan SHA-256", f"H(pesan) = {r['digest']}",
                 "Hash membuat pesan sepanjang apa pun menjadi sidik jari 256 bit."),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("Langkah 2 - Kecilkan hash agar &lt; n", f"h = H(pesan) mod {r['n']} = <b>{r['h']}</b>",
                 "Hash 256 bit lebih besar dari n kecil, jadi diambil sisa baginya.", "s2"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("Langkah 3 - Tanda tangani dengan kunci privat",
                 f"s = h<sup>d</sup> mod n = {r['h']}<sup>{r['d']}</sup> mod {r['n']} = <b>{r['s']}</b>",
                 css="s3"),
        unsafe_allow_html=True,
    )
    section("Hasil")
    st.markdown(result_box("Tanda tangan digital (s)", str(r["s"]), "dec"), unsafe_allow_html=True)
    st.caption(
        f"Kirim pesan, tanda tangan s, dan kunci publik (e, n) = ({r['e']}, {r['n']}) "
        "ke penerima. Penerima memakai tab verifikasi untuk mengecek keasliannya."
    )


def render_ver_result(r):
    """Hasil verifikasi tanda tangan."""
    section("Proses Verifikasi")
    st.markdown(
        step_box("Langkah 1 - Hash pesan dengan SHA-256", f"H(pesan) = {r['digest']}"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("Langkah 2 - Kecilkan hash agar &lt; n", f"h = H(pesan) mod {r['n']} = <b>{r['h']}</b>",
                 css="s2"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("Langkah 3 - Buka tanda tangan dengan kunci publik",
                 f"v = s<sup>e</sup> mod n = {r['s']}<sup>{r['e']}</sup> mod {r['n']} = <b>{r['v']}</b>",
                 css="s3"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("Langkah 4 - Bandingkan", f"v = h ? &rarr; {r['v']} {'=' if r['ok'] else '&ne;'} {r['h']}",
                 css="s4"),
        unsafe_allow_html=True,
    )
    section("Hasil")
    if r["ok"]:
        st.markdown(
            result_box("Tanda tangan VALID", "Pesan asli dan ditandatangani oleh pemilik kunci privat "
                       "yang berpasangan dengan kunci publik ini.", "good"),
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            result_box("Tanda tangan TIDAK VALID", "Pesan sudah diubah, atau tanda tangan / kunci publik "
                       "(e, n) tidak cocok.", "bad"),
            unsafe_allow_html=True,
        )


def page_ttd_buat():
    section("Input Tanda Tangan")
    col1, col2, col3 = st.columns(3)
    p = int(col1.number_input("p (prima)", min_value=2, max_value=10**7, value=1009,
                              step=1, key="sig_p"))
    q = int(col2.number_input("q (prima)", min_value=2, max_value=10**7, value=1013,
                              step=1, key="sig_q"))
    e_input = int(col3.number_input("e (0 = otomatis)", min_value=0, max_value=10**14,
                                    value=0, step=1, key="sig_e"))
    keys_ok = True
    try:
        n, phi, e, d = generate_keys(p, q, e_input or None)
    except ValueError as ex:
        st.error(str(ex))
        keys_ok = False

    msg = st.text_area("Pesan yang ditandatangani", height=120, key="sig_msg",
                       placeholder="Ketik pesan yang mau ditandatangani...")
    if keys_ok and st.button("Tanda tangani", key="btn_sig"):
        if not msg.strip():
            st.warning("Isi pesan dulu.")
        else:
            digest, h, sgn = sign_message(msg, d, n)
            st.session_state["sig_result"] = {
                "p": p, "q": q, "e_input": e_input, "n": n, "phi": phi, "e": e, "d": d,
                "digest": digest, "h": h, "s": sgn, "chk": (p, q, e_input, msg),
            }
    r = st.session_state.get("sig_result")
    if r:
        cur = (p, q, e_input, msg) if keys_ok else None
        if cur != r.get("chk"):
            st.warning("Hasil di bawah berasal dari input sebelumnya. "
                       "Tekan Tanda tangani lagi untuk memperbarui.")
        render_sig_result(r)


def page_ttd_verif():
    section("Input Verifikasi")
    col1, col2 = st.columns(2)
    e = col1.number_input("e (kunci publik)", min_value=1, max_value=10**15, value=None,
                          step=1, placeholder="mis. 3", key="ver_e")
    n = col2.number_input("n", min_value=1, max_value=10**15, value=None,
                          step=1, placeholder="mis. 1022117", key="ver_n")
    sgn = st.number_input("Tanda tangan (s)", min_value=0, max_value=10**15, value=None,
                          step=1, placeholder="Tempel tanda tangan di sini", key="ver_s")
    msg = st.text_area("Pesan yang diverifikasi", height=120, key="ver_msg",
                       placeholder="Tempel pesan yang diterima...")
    st.caption("Pesan harus sama persis, termasuk spasi dan huruf besar/kecil. "
               "Coba ubah satu huruf: verifikasi akan gagal.")

    cur = None
    if e is None or n is None or sgn is None:
        st.info("Isi e, n, dan tanda tangan terlebih dahulu.")
    elif int(n) < 2:
        st.error("n harus lebih besar dari 1.")
    else:
        e, n, sgn = int(e), int(n), int(sgn)
        cur = (e, n, sgn, msg)
        if st.button("Verifikasi", key="btn_ver"):
            if not msg.strip():
                st.warning("Isi pesan dulu.")
            elif sgn >= n:
                st.session_state["ver_result"] = None
                st.error("Tanda tangan harus lebih kecil dari n.")
            else:
                digest, h, v, ok = verify_signature(msg, sgn, e, n)
                st.session_state["ver_result"] = {
                    "e": e, "n": n, "s": sgn, "digest": digest, "h": h, "v": v,
                    "ok": ok, "chk": cur,
                }
    r = st.session_state.get("ver_result")
    if r:
        if cur != r.get("chk"):
            st.warning("Hasil di bawah berasal dari input sebelumnya. "
                       "Tekan Verifikasi lagi untuk memperbarui.")
        render_ver_result(r)


def page_tanda_tangan():
    mode = st.radio("Mode", ["Buat tanda tangan", "Verifikasi tanda tangan"],
                    horizontal=True, key="sig_mode", label_visibility="collapsed")
    if mode == "Buat tanda tangan":
        page_ttd_buat()
    else:
        page_ttd_verif()


# ---------------- Halaman Tentang ----------------
def page_tentang():
    section("Cara kerja")
    st.markdown(
        step_box("1. Pesan menjadi angka",
                 "Tiap huruf diubah ke kode 2 digit (A=01, B=02, ..., Z=26), "
                 "lalu semua digit disambung."),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("2. Angka dipecah menjadi blok",
                 "Digit dipotong per k digit. Nilai tiap blok harus lebih kecil dari n.", css="s2"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("3. Tiap blok dienkripsi",
                 "c = m<sup>e</sup> mod n dengan kunci publik (e, n). "
                 "Dekripsi memakai m = c<sup>d</sup> mod n dengan kunci privat (d, n).", css="s3"),
        unsafe_allow_html=True,
    )
    st.markdown(
        step_box("4. Tanda tangan digital",
                 "Pesan di-hash (SHA-256), lalu s = h<sup>d</sup> mod n dengan kunci privat. "
                 "Penerima mengecek s<sup>e</sup> mod n = h dengan kunci publik.", css="s4"),
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
  <div class="ttl">&epsilon; Kalkulator RSA 26 Huruf &#1079;</div>
  <div class="sub">Enkripsi dan dekripsi pesan huruf A-Z (A=01 ... Z=26). p dan q kamu tentukan sendiri.</div>
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

tab_enc, tab_dec, tab_sig, tab_info = st.tabs(
    ["👤 Enkripsi", "ℹ️ Dekripsi", "✍️ Tanda Tangan", "☰ Tentang"]
)

with tab_enc:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_enkripsi()

with tab_dec:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_dekripsi()

with tab_sig:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_tanda_tangan()

with tab_info:
    st.markdown(BAND_HTML, unsafe_allow_html=True)
    with st.container(border=True):
        page_tentang()
