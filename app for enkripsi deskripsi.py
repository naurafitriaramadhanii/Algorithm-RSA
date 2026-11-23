    n = col2.number_input("n", min_value=1, max_value=10**15, value=None,
                          step=1, placeholder="mis. 1022117", key="dec_n")

    cipher = st.text_area("Ciphertext (angka dipisah spasi)", height=120, key="cipher",
                          placeholder="Tempel ciphertext di sini...")

    cur_sig = None
    if d is None or n is None:
        st.info("Isi d dan n terlebih dahulu.")
    elif int(n) <= 127:
        st.error("n harus lebih besar dari 127 untuk kode ASCII.")
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
