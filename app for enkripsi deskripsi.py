def valid_e_list(phi: int, limit: int = 15):
    """Daftar e terkecil yang relatif prima dengan phi."""
    out, e = [], 2
    while e < phi and len(out) < limit:
        if gcd(e, phi) == 1:
            out.append(e)
        e += 1
    return out


def blocks_of(plain: str, k: int):
    """Pecah plaintext per k karakter -> list (teks, digit ASCII, m)."""
    res = []
    for i in range(0, len(plain), k):
        chunk = plain[i:i + k]
        digits = "".join(f"{ord(ch):03d}" for ch in chunk)
        res.append((chunk, digits, int(digits)))
    return res


def auto_block_size(plain: str, n: int) -> int:
    """Ukuran blok terbesar (maks 20) sehingga semua m < n."""
    for k in range(20, 0, -1):
        if all(m < n for _, _, m in blocks_of(plain, k)):
            return k
    return 1


def page_encrypt():
    st.title("🔒 Enkripsi RSA")

    c1, c2 = st.columns(2)
    p_txt = c1.text_input("p (bilangan prima)", key="enc_p")
    q_txt = c2.text_input("q (bilangan prima)", key="enc_q")
    plain = st.text_area("Plaintext", height=120, key="enc_plain")

    if not (p_txt.strip() and q_txt.strip()):
        st.info("Isi p dan q (bilangan prima) dulu, e dan hasil enkripsi akan dihitung otomatis.")
        return

    try:
        p, q = parse_int(p_txt, "p"), parse_int(q_txt, "q")
        if not is_prime(p):
            raise ValueError(f"p = {p} bukan bilangan prima.")
        if not is_prime(q):
            raise ValueError(f"q = {q} bukan bilangan prima.")
        if p == q:
            raise ValueError("p dan q harus berbeda.")
        phi = (p - 1) * (q - 1)
        if phi < 3:
            raise ValueError("p dan q terlalu kecil, tidak ada e yang valid.")

        # ---- pilih e ----
        valid_es = valid_e_list(phi)
        mode = st.radio("Kunci publik e",
                        ["Otomatis (terkecil)", "Pilih dari daftar valid", "Manual"],
                        horizontal=True)
        if mode.startswith("Otomatis"):
            e = valid_es[0]
            st.caption(f"e = {e} (e terkecil dengan gcd(e, φ(n)) = 1)")
        elif mode.startswith("Pilih"):
            e = st.selectbox("Pilih e", valid_es)
        else:
            e = parse_int(st.text_input("Masukkan e", key="enc_e_manual"), "e")

        key = build_key(p, q, e)
        n, d = key["n"], key["d"]

        # ---- ringkasan kunci ----
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("n = p × q", n)
        m2.metric("φ(n)", phi)
        m3.metric("Kunci Publik (e, n)", f"({e}, {n})")
        m4.metric("Kunci Privat (d, n)", f"({d}, {n})")
        with st.expander("🔑 Langkah pembangkitan kunci"):
            render_key(key)

        # ---- enkripsi ----
        if not plain:
            st.info("Ketik plaintext untuk melihat hasil enkripsi.")
            return
        bad = [ch for ch in plain if not (1 <= ord(ch) <= 127)]
        if bad:
            raise ValueError(f"Karakter '{bad[0]}' di luar jangkauan ASCII (1-127).")

        auto = st.checkbox("Ukuran blok otomatis (terbesar yang masih aman)", value=True)
        if auto:
            k = auto_block_size(plain, n)
            st.caption(f"Ukuran blok = {k} karakter")
        else:
            k = int(st.number_input("Ukuran blok (karakter per blok)", 1, 20, 1, 1))

        rows, cipher_blocks = [], []
        for idx, (chunk, digits, m) in enumerate(blocks_of(plain, k), start=1):
            if m >= n:
                raise ValueError(
                    f"Blok ke-{idx} ('{chunk}') bernilai m = {m} ≥ n = {n}. "
                    "Perkecil ukuran blok atau gunakan p dan q yang lebih besar.")
            c = pow(m, e, n)
            rows.append({"Blok": idx, "Teks": chunk, "ASCII (m)": digits,
                         "c = m^e mod n": str(c)})
            cipher_blocks.append(str(c))

        cipher = " ".join(cipher_blocks)
        st.session_state["last_enc"] = {"d": str(d), "n": str(n), "cipher": cipher}

        st.subheader("Ciphertext")
        st.code(cipher, language=None)
        st.subheader("Perhitungan per blok")
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    except ValueError as err:
        st.error(str(err))
