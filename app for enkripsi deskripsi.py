
"""
RSA CRYPTOGRAPHY STUDIO
Aplikasi Enkripsi & Dekripsi RSA
Jalankan: streamlit run app.py
"""

from math import gcd
import streamlit as st


# =====================================================
# 1. KONFIGURASI HALAMAN
# =====================================================

st.set_page_config(
    page_title="RSA Cryptography Studio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# =====================================================
# 2. CUSTOM CSS
# =====================================================

st.markdown("""
<style>

/* IMPORT FONT */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

/* GLOBAL */
.stApp {
    background: linear-gradient(135deg, #090d20 0%, #11152e 50%, #171438 100%);
    color: #f1f5ff;
    font-family: 'Inter', sans-serif;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1250px;
}

/* HIDE STREAMLIT ELEMENTS */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* TEXT */
h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: #ffffff !important;
}

p, label, span {
    color: #d5dcf5;
}

/* HERO */
.hero {
    background: linear-gradient(120deg, #312e81, #6d28d9, #2563eb);
    padding: 42px 38px;
    border-radius: 25px;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 12px 40px rgba(91, 64, 220, 0.25);
}

.hero h1 {
    font-size: 42px !important;
    font-weight: 800;
    margin-bottom: 8px;
}

.hero p {
    font-size: 15px;
    color: #e0e7ff;
}

.hero-tag {
    display: inline-block;
    background: rgba(255,255,255,0.15);
    border: 1px solid rgba(255,255,255,0.25);
    padding: 7px 14px;
    border-radius: 30px;
    font-size: 12px;
    margin-bottom: 15px;
    color: white;
}

/* SECTION */
.section-title {
    font-size: 23px;
    font-weight: 700;
    color: #ffffff;
    margin-top: 30px;
    margin-bottom: 15px;
    font-family: 'Space Grotesk', sans-serif;
}

.section-desc {
    color: #a5b4d4;
    font-size: 13px;
    margin-bottom: 20px;
}

/* CARDS */
.info-card {
    background: linear-gradient(145deg, #1b2142, #151a35);
    border: 1px solid #303b69;
    border-radius: 18px;
    padding: 20px;
    min-height: 125px;
    transition: 0.3s ease;
}

.info-card:hover {
    border-color: #818cf8;
    transform: translateY(-4px);
}

.card-label {
    font-size: 12px;
    color: #a5b4d4;
    margin-bottom: 12px;
}

.card-value {
    font-size: 28px;
    font-weight: 800;
    color: #a5b4fc;
    font-family: 'Space Grotesk', sans-serif;
    overflow-wrap: anywhere;
}

.card-icon {
    font-size: 23px;
    margin-bottom: 8px;
}

/* KEY CARDS */
.key-card {
    background: linear-gradient(135deg, #22265a, #312e81);
    border: 1px solid #6366f1;
    border-radius: 18px;
    padding: 22px;
    min-height: 150px;
}

.key-card.private {
    background: linear-gradient(135deg, #3b1f59, #581c87);
    border-color: #c084fc;
}

.key-title {
    font-size: 13px;
    color: #c7d2fe;
    margin-bottom: 12px;
}

.key-value {
    font-size: 20px;
    font-weight: 700;
    color: white;
    overflow-wrap: anywhere;
}

/* INPUT */
.stTextInput input,
.stTextArea textarea,
.stNumberInput input {
    background-color: #171e3b !important;
    color: white !important;
    border: 1px solid #394675 !important;
    border-radius: 12px !important;
}

.stTextArea textarea {
    line-height: 1.7;
}

.stNumberInput button {
    background: #312e81 !important;
    color: white !important;
}

/* BUTTON */
.stButton > button {
    background: linear-gradient(90deg, #6366f1, #8b5cf6);
    color: white !important;
    border: none;
    border-radius: 12px;
    padding: 12px 20px;
    font-weight: 700;
    min-height: 45px;
    transition: 0.3s;
}

.stButton > button:hover {
    background: linear-gradient(90deg, #4f46e5, #7c3aed);
    border: 1px solid #a5b4fc;
    transform: translateY(-2px);
}

/* TABS */
.stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    background: #171e3b;
    padding: 8px;
    border-radius: 14px;
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 10px;
    color: #c7d2fe;
    padding: 12px 20px;
}

.stTabs [aria-selected="true"] {
    background: #4f46e5 !important;
    color: white !important;
}

/* ALERT */
.stAlert {
    border-radius: 12px;
}

/* PROCESS */
.process-card {
    background: #1a2142;
    border: 1px solid #374578;
    border-radius: 15px;
    padding: 17px;
    text-align: center;
    height: 100%;
}

.process-number {
    color: #a5b4fc;
    font-size: 25px;
    font-weight: 800;
}

.process-name {
    color: white;
    font-weight: 700;
    margin-top: 7px;
}

.process-desc {
    color: #a5b4d4;
    font-size: 12px;
    margin-top: 7px;
}

/* FOOTER */
.footer {
    text-align: center;
    color: #7885aa;
    font-size: 12px;
    border-top: 1px solid #30385e;
    padding-top: 25px;
    margin-top: 50px;
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# 3. LOGIKA RSA
# =====================================================

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
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError("Invers modular tidak ditemukan.")

    return old_s % phi


def generate_keys(p, q, e=None):

    if not is_prime(p) or not is_prime(q):
        raise ValueError("p dan q harus bilangan prima.")

    if p == q:
        raise ValueError("p dan q tidak boleh sama.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if phi <= 3:
        raise ValueError("Gunakan bilangan prima yang lebih besar.")

    if e is None:
        e = 3

        while e < phi and gcd(e, phi) != 1:
            e += 2

        if e >= phi:
            raise ValueError("Tidak ditemukan nilai e yang valid.")

    elif not (1 < e < phi) or gcd(e, phi) != 1:
        raise ValueError(
            f"e harus memenuhi 1 < e < {phi} "
            "dan FPB(e, phi) = 1."
        )

    d = mod_inverse(e, phi)

    return n, phi, e, d


def encrypt(message, e, n):

    codes = [ord(char) for char in message]

    if codes and max(codes) >= n:
        raise ValueError(
            f"Nilai n = {n} terlalu kecil. "
            f"Karakter terbesar membutuhkan n > {max(codes)}."
        )

    encrypted = [pow(m, e, n) for m in codes]

    return " ".join(map(str, encrypted))


def decrypt(cipher, d, n):

    try:
        nums = [int(x) for x in cipher.split()]
    except ValueError:
        raise ValueError("Ciphertext harus berisi angka yang dipisahkan spasi.")

    if not nums:
        raise ValueError("Ciphertext masih kosong.")

    if any(x < 0 or x >= n for x in nums):
        raise ValueError("Terdapat angka ciphertext di luar rentang yang valid.")

    decrypted = [pow(c, d, n) for c in nums]

    try:
        return "".join(chr(x) for x in decrypted)
    except ValueError:
        raise ValueError("Hasil dekripsi tidak valid.")


# =====================================================
# 4. HEADER / HERO SECTION
# =====================================================

st.markdown("""
<div class="hero">
    <div class="hero-tag">✦ CRYPTOGRAPHY LEARNING PLATFORM</div>
    <h1>🔐 RSA Cryptography Studio</h1>
    <p>
        Explore the world of cryptography through RSA.
        Generate keys, encrypt messages, and decrypt ciphertext
        in one interactive platform.
    </p>
</div>
""", unsafe_allow_html=True)


# =====================================================
# 5. SIDEBAR INFORMASI
# =====================================================

with st.sidebar:

    st.markdown("## 🔐 RSA Studio")

    st.caption("Cryptography Learning Platform")

    st.divider()

    st.markdown("### 📚 About RSA")

    st.write("""
    RSA merupakan algoritma kriptografi asimetris
    yang menggunakan dua jenis kunci:

    - 🔓 Public Key
    - 🔒 Private Key

    RSA menggunakan konsep bilangan prima,
    aritmetika modular, dan faktorisasi.
    """)

    st.divider()

    st.markdown("### ⚙️ Algorithm")

    st.code("""
n = p × q

φ(n) = (p-1)(q-1)

C = M^e mod n

M = C^d mod n
    """)

    st.info("Aplikasi ini dibuat untuk tujuan pembelajaran.")


# =====================================================
# 6. INPUT KUNCI
# =====================================================

st.markdown(
    '<div class="section-title">⚙️ Key Generator</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="section-desc">Masukkan dua bilangan prima untuk menghasilkan pasangan kunci RSA.</div>',
    unsafe_allow_html=True
)

col1, col2, col3 = st.columns(3)

with col1:
    p = st.number_input(
        "🔢 Bilangan Prima (p)",
        min_value=2,
        value=1009,
        step=1
    )

with col2:
    q = st.number_input(
        "🔢 Bilangan Prima (q)",
        min_value=2,
        value=1013,
        step=1
    )

with col3:
    e_input = st.number_input(
        "🔑 Public Exponent (e)",
        min_value=0,
        value=0,
        step=1,
        help="Isi 0 untuk menghasilkan e secara otomatis."
    )


# =====================================================
# 7. GENERATE KEYS
# =====================================================

keys = None

try:
    keys = generate_keys(
        int(p),
        int(q),
        int(e_input) if e_input != 0 else None
    )

except ValueError as ex:
    st.error(f"⚠️ {ex}")


if keys:

    n, phi, e, d = keys

    st.success("✅ Pasangan kunci RSA berhasil dihasilkan!")

    # DASHBOARD METRICS

    st.markdown(
        '<div class="section-title">📊 RSA Key Dashboard</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    metrics = [
        (c1, "🔢", "Prime Number p", p),
        (c2, "🔢", "Prime Number q", q),
        (c3, "🔷", "Modulus n", n),
        (c4, "🧮", "Totient φ(n)", phi)
    ]

    for col, icon, label, value in metrics:

        with col:
            st.markdown(f"""
            <div class="info-card">
                <div class="card-icon">{icon}</div>
                <div class="card-label">{label}</div>
                <div class="card-value">{value:,}</div>
            </div>
            """, unsafe_allow_html=True)

    # KEY DISPLAY

    st.markdown(
        '<div class="section-title">🗝️ Generated Key Pairs</div>',
        unsafe_allow_html=True
    )

    key1, key2 = st.columns(2)

    with key1:
        st.markdown(f"""
        <div class="key-card">
            <div class="key-title">🔓 PUBLIC KEY</div>
            <div class="key-value">(e, n)</div>
            <br>
            <div class="key-value">({e}, {n})</div>
            <p style="color:#c7d2fe;font-size:12px;">
                Digunakan untuk mengenkripsi pesan.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with key2:
        st.markdown(f"""
        <div class="key-card private">
            <div class="key-title">🔒 PRIVATE KEY</div>
            <div class="key-value">(d, n)</div>
            <br>
            <div class="key-value">({d}, {n})</div>
            <p style="color:#e9d5ff;font-size:12px;">
                Digunakan untuk mendekripsi pesan.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with st.expander("📖 Lihat proses pembentukan kunci RSA"):

        st.markdown(f"""
        **Langkah 1 — Menghitung modulus**

        n = p × q = {p} × {q} = **{n}**

        **Langkah 2 — Menghitung Euler's Totient**

        φ(n) = (p - 1)(q - 1)

        = ({p}-1) × ({q}-1)

        = **{phi}**

        **Langkah 3 — Menentukan Public Exponent**

        e = **{e}**

        FPB(e, φ(n)) = {gcd(e, phi)}

        **Langkah 4 — Menghitung Private Exponent**

        d = e⁻¹ mod φ(n)

        d = **{d}**

        Sehingga diperoleh:

        - Public Key = ({e}, {n})
        - Private Key = ({d}, {n})
        """)

    # =================================================
    # 8. ENCRYPTION & DECRYPTION
    # =================================================

    st.markdown(
        '<div class="section-title">💻 Message Encryption & Decryption</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-desc">Ubah pesan menjadi ciphertext atau kembalikan ciphertext menjadi plaintext.</div>',
        unsafe_allow_html=True
    )

    tab_enc, tab_dec, tab_info = st.tabs([
        "🔒 ENCRYPTION",
        "🔓 DECRYPTION",
        "📚 HOW RSA WORKS"
    ])

    # ================= ENCRYPTION =================

    with tab_enc:

        st.markdown("### ✉️ Encrypt Your Message")

        st.caption(
            "Masukkan pesan yang ingin dienkripsi menggunakan Public Key."
        )

        plain = st.text_area(
            "Plaintext",
            placeholder="Contoh: HARI INI BELAJAR KRIPTOGRAFI...",
            height=130,
            key="plain"
        )

        st.caption(f"Karakter: {len(plain)}")

        if st.button("🔐 ENCRYPT MESSAGE", key="btn_encrypt", use_container_width=True):

            if not plain:
                st.warning("Masukkan plaintext terlebih dahulu.")

            else:
                try:

                    result = encrypt(plain, e, n)

                    st.session_state["encrypted_result"] = result

                    st.success("✨ Pesan berhasil dienkripsi!")

                except ValueError as ex:
                    st.error(str(ex))

        if "encrypted_result" in st.session_state:

            st.markdown("#### 📦 Ciphertext Result")

            st.text_area(
                "Hasil Enkripsi",
                value=st.session_state["encrypted_result"],
                height=130,
                key="enc_output"
            )

            st.caption(
                "Ciphertext merupakan kumpulan angka hasil proses enkripsi."
            )

            st.code(st.session_state["encrypted_result"], language="text")

    # ================= DECRYPTION =================

    with tab_dec:

        st.markdown("### 🔓 Decrypt Your Message")

        st.caption(
            "Masukkan ciphertext untuk mengembalikan pesan asli menggunakan Private Key."
        )

        cipher = st.text_area(
            "Ciphertext",
            placeholder="Contoh: 12345 67890 23456",
            height=130,
            key="cipher"
        )

        if st.button("🔓 DECRYPT MESSAGE", key="btn_decrypt", use_container_width=True):

            if not cipher.strip():
                st.warning("Masukkan ciphertext terlebih dahulu.")

            else:
                try:

                    result = decrypt(cipher, d, n)

                    st.session_state["decrypted_result"] = result

                    st.success("✨ Pesan berhasil didekripsi!")

                except ValueError as ex:
                    st.error(str(ex))

        if "decrypted_result" in st.session_state:

            st.markdown("#### 💬 Decrypted Plaintext")

            st.text_area(
                "Hasil Dekripsi",
                value=st.session_state["decrypted_result"],
                height=130,
                key="dec_output"
            )

    # ================= HOW RSA WORKS =================

    with tab_info:

        st.markdown("### 🧠 Understanding RSA Process")

        st.write(
            "RSA bekerja melalui dua proses utama, yaitu enkripsi "
            "dan dekripsi menggunakan pasangan kunci yang berbeda."
        )

        st.markdown("#### 🔒 Encryption Flow")

        a, b, c = st.columns(3)

        with a:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">01</div>
                <div class="process-name">Plaintext</div>
                <div class="process-desc">
                    Pesan asli diubah menjadi nilai numerik.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with b:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">02</div>
                <div class="process-name">Encryption</div>
                <div class="process-desc">
                    Menggunakan Public Key untuk melakukan enkripsi.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with c:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">03</div>
                <div class="process-name">Ciphertext</div>
                <div class="process-desc">
                    Menghasilkan pesan dalam bentuk terenkripsi.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### 🔓 Decryption Flow")

        a, b, c = st.columns(3)

        with a:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">01</div>
                <div class="process-name">Ciphertext</div>
                <div class="process-desc">
                    Memasukkan pesan yang sudah dienkripsi.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with b:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">02</div>
                <div class="process-name">Decryption</div>
                <div class="process-desc">
                    Menggunakan Private Key untuk mendekripsi.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with c:
            st.markdown("""
            <div class="process-card">
                <div class="process-number">03</div>
                <div class="process-name">Plaintext</div>
                <div class="process-desc">
                    Mendapatkan kembali pesan aslinya.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        st.markdown("#### 📐 RSA Mathematical Formula")

        col1, col2 = st.columns(2)

        with col1:
            st.info("🔒 ENCRYPTION")
            st.latex(r"C = M^e \mod n")

        with col2:
            st.success("🔓 DECRYPTION")
            st.latex(r"M = C^d \mod n")

        st.caption("""
        M = Plaintext | C = Ciphertext | e = Public Exponent
        | d = Private Exponent | n = Modulus
        """)


# =====================================================
# 9. FOOTER
# =====================================================

st.markdown("""
<div class="footer">
    <p>🔐 RSA CRYPTOGRAPHY STUDIO</p>
    <p>Interactive Cryptography Learning Platform</p>
    <p>Made for Educational Purposes ✦</p>
    <p>© 2026 RSA Learning Project</p>
</div>
""", unsafe_allow_html=True)
