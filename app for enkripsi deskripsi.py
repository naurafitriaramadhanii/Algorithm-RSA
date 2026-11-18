"""
Aplikasi Enkripsi & Dekripsi RSA (input p dan q manual)
Jalankan: python rsa_app.py
Catatan: untuk edukasi. Jangan dipakai untuk mengamankan data sungguhan.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from math import gcd


# ---------------- Logika RSA ----------------
def is_prime(n: int) -> bool:
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


def mod_inverse(e: int, phi: int) -> int:
    """Invers modular lewat extended Euclidean."""
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
        # pilih e terkecil > 1 yang koprima dengan phi
        e = 3
        while e < phi and gcd(e, phi) != 1:
            e += 2
        if e >= phi:
            raise ValueError("Tidak ada e yang valid, coba p dan q lain.")
    else:
        if not (1 < e < phi) or gcd(e, phi) != 1:
            raise ValueError(f"e harus 1 < e < {phi} dan koprima dengan phi(n).")
    d = mod_inverse(e, phi)
    return n, phi, e, d


def encrypt(text: str, e: int, n: int) -> str:
    codes = [ord(c) for c in text]
    if codes and max(codes) >= n:
        raise ValueError(
            f"n ({n}) terlalu kecil untuk pesan ini. "
            f"Butuh n > {max(codes)}. Gunakan p dan q yang lebih besar."
        )
    return " ".join(str(pow(m, e, n)) for m in codes)


def decrypt(cipher: str, d: int, n: int) -> str:
    nums = [int(x) for x in cipher.split()]
    return "".join(chr(pow(c, d, n)) for c in nums)


# ---------------- GUI ----------------
class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplikasi Enkripsi & Dekripsi RSA")
        self.geometry("720x640")
        self.keys = None  # (n, phi, e, d)
        self._build()

    def _build(self):
        pad = {"padx": 8, "pady": 4}

        # --- Input kunci ---
        frm = ttk.LabelFrame(self, text="1. Input Kunci")
        frm.pack(fill="x", **pad)

        ttk.Label(frm, text="p (prima):").grid(row=0, column=0, sticky="e", **pad)
        self.ent_p = ttk.Entry(frm, width=20)
        self.ent_p.grid(row=0, column=1, **pad)

        ttk.Label(frm, text="q (prima):").grid(row=0, column=2, sticky="e", **pad)
        self.ent_q = ttk.Entry(frm, width=20)
        self.ent_q.grid(row=0, column=3, **pad)

        ttk.Label(frm, text="e (opsional):").grid(row=1, column=0, sticky="e", **pad)
        self.ent_e = ttk.Entry(frm, width=20)
        self.ent_e.grid(row=1, column=1, **pad)

        ttk.Button(frm, text="Generate Kunci", command=self.on_generate).grid(
            row=1, column=3, sticky="e", **pad
        )

        self.lbl_keys = ttk.Label(frm, text="Belum ada kunci.", justify="left")
        self.lbl_keys.grid(row=2, column=0, columnspan=4, sticky="w", **pad)

        # --- Plaintext ---
        frm2 = ttk.LabelFrame(self, text="2. Enkripsi (Plaintext → Ciphertext)")
        frm2.pack(fill="both", expand=True, **pad)
        self.txt_plain = tk.Text(frm2, height=5, wrap="word")
        self.txt_plain.pack(fill="both", expand=True, **pad)
        ttk.Button(frm2, text="Enkripsi", command=self.on_encrypt).pack(anchor="e", **pad)

        # --- Ciphertext ---
        frm3 = ttk.LabelFrame(self, text="3. Dekripsi (Ciphertext → Plaintext)")
        frm3.pack(fill="both", expand=True, **pad)
        self.txt_cipher = tk.Text(frm3, height=5, wrap="word")
        self.txt_cipher.pack(fill="both", expand=True, **pad)
        ttk.Button(frm3, text="Dekripsi", command=self.on_decrypt).pack(anchor="e", **pad)

        # --- Hasil ---
        frm4 = ttk.LabelFrame(self, text="Hasil")
        frm4.pack(fill="both", expand=True, **pad)
        self.txt_out = tk.Text(frm4, height=5, wrap="word", state="normal")
        self.txt_out.pack(fill="both", expand=True, **pad)

    # --- helpers ---
    def _set_out(self, text):
        self.txt_out.delete("1.0", "end")
        self.txt_out.insert("1.0", text)

    def _need_keys(self):
        if not self.keys:
            messagebox.showwarning("Kunci belum ada", "Generate kunci dulu (isi p dan q).")
            return False
        return True

    # --- actions ---
    def on_generate(self):
        try:
            p = int(self.ent_p.get().strip())
            q = int(self.ent_q.get().strip())
            e_txt = self.ent_e.get().strip()
            e = int(e_txt) if e_txt else None
            self.keys = generate_keys(p, q, e)
        except ValueError as ex:
            self.keys = None
            messagebox.showerror("Error", str(ex))
            return
        n, phi, e, d = self.keys
        self.lbl_keys.config(
            text=(
                f"n = p × q = {n}\n"
                f"φ(n) = (p-1)(q-1) = {phi}\n"
                f"Kunci Publik  (e, n) = ({e}, {n})\n"
                f"Kunci Privat  (d, n) = ({d}, {n})"
            )
        )

    def on_encrypt(self):
        if not self._need_keys():
            return
        n, _, e, _ = self.keys
        plain = self.txt_plain.get("1.0", "end-1c")
        if not plain:
            messagebox.showinfo("Kosong", "Isi plaintext dulu.")
            return
        try:
            cipher = encrypt(plain, e, n)
        except ValueError as ex:
            messagebox.showerror("Error", str(ex))
            return
        self._set_out(cipher)
        self.txt_cipher.delete("1.0", "end")
        self.txt_cipher.insert("1.0", cipher)

    def on_decrypt(self):
        if not self._need_keys():
            return
        n, _, _, d = self.keys
        cipher = self.txt_cipher.get("1.0", "end-1c").strip()
        if not cipher:
            messagebox.showinfo("Kosong", "Isi ciphertext dulu.")
            return
        try:
            plain = decrypt(cipher, d, n)
        except (ValueError, OverflowError):
            messagebox.showerror(
                "Error", "Ciphertext tidak valid atau kunci (p, q) tidak cocok."
            )
            return
        self._set_out(plain)


if __name__ == "__main__":
    RSAApp().mainloop()
