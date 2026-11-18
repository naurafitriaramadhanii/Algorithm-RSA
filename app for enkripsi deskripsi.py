"""
Kalkulator RSA berbasis ASCII (GUI Tkinter)

Cara kerja:
- Setiap karakter diubah ke kode ASCII 3 digit (mis. 'A' -> 065, spasi -> 032).
- Plaintext dipecah per blok (ukuran blok = jumlah karakter per blok, dipilih user).
- Kode ASCII tiap blok digabung jadi satu angka m, lalu: c = m^e mod n.
- Dekripsi: m = c^d mod n, lalu m dipecah lagi per 3 digit menjadi karakter.

Jalankan: python kalkulator_rsa.py   (Python 3.8+)
"""

import re
import tkinter as tk
from tkinter import ttk, messagebox
from math import gcd

# ----------------------------------------------------------------------
# Fungsi matematika
# ----------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Uji bilangan prima (Miller-Rabin deterministik untuk n < 3,3 x 10^24)."""
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
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def euclid_inverse(e: int, phi: int):
    """Mengembalikan (d, langkah) dengan d = e^-1 mod phi memakai Euclid diperluas."""
    steps = []
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        steps.append(f"{old_r} = {q} × {r} + {old_r - q * r}")
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi, steps


def build_key(p: int, q: int, e: int):
    """Validasi input dan bangkitkan kunci. Mengembalikan dict info kunci."""
    if not is_prime(p):
        raise ValueError(f"p = {p} bukan bilangan prima.")
    if not is_prime(q):
        raise ValueError(f"q = {q} bukan bilangan prima.")
    if p == q:
        raise ValueError("p dan q harus berbeda.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not (1 < e < phi):
        raise ValueError(f"e harus memenuhi 1 < e < φ(n) = {phi}.")
    if gcd(e, phi) != 1:
        raise ValueError(f"e = {e} tidak relatif prima dengan φ(n) = {phi} (gcd ≠ 1).")
    d, steps = euclid_inverse(e, phi)
    return {"p": p, "q": q, "e": e, "n": n, "phi": phi, "d": d, "steps": steps}


# ----------------------------------------------------------------------
# Helper UI
# ----------------------------------------------------------------------

def set_text(widget: tk.Text, content: str):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.config(state="disabled")


def make_table(parent, columns, widths, height=8):
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[c for c, _ in columns], show="headings", height=height)
    for (cid, title), w in zip(columns, widths):
        tree.heading(cid, text=title)
        tree.column(cid, width=w, anchor="center")
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return frame, tree


def parse_int(text: str, name: str) -> int:
    text = text.strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError(f"{name} harus berupa bilangan bulat positif.")
    return int(text)


# ----------------------------------------------------------------------
# Halaman
# ----------------------------------------------------------------------

class HomeFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        box = ttk.Frame(self)
        box.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(box, text="🔐", font=("Segoe UI Emoji", 48)).pack()
        ttk.Label(box, text="Kalkulator RSA", font=("Segoe UI", 32, "bold")).pack(pady=(5, 0))
        ttk.Label(box, text="Enkripsi & Dekripsi berbasis ASCII", font=("Segoe UI", 14)).pack(pady=5)
        ttk.Label(
            box,
            text="Selamat datang! Pilih menu Enkripsi atau Dekripsi di samping untuk memulai.",
            font=("Segoe UI", 11),
            foreground="#666666",
        ).pack(pady=(20, 0))


class EncryptFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=15)
        self.key_info = None
        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="Enkripsi RSA", font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.p_var, self.q_var, self.e_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for i, (label, var) in enumerate([("p (prima)", self.p_var),
                                          ("q (prima)", self.q_var),
                                          ("e (kunci publik)", self.e_var)], start=1):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(self, textvariable=var, width=30).grid(row=i, column=1, sticky="w", pady=3)

        ttk.Label(self, text="Plaintext").grid(row=4, column=0, sticky="nw", pady=3)
        self.plain = tk.Text(self, height=4, width=60, wrap="word")
        self.plain.grid(row=4, column=1, columnspan=2, sticky="ew", pady=3)

        ttk.Label(self, text="Ukuran blok\n(karakter/blok)").grid(row=5, column=0, sticky="w", pady=3)
        self.block_var = tk.IntVar(value=1)
        ttk.Spinbox(self, from_=1, to=20, textvariable=self.block_var, width=8).grid(
            row=5, column=1, sticky="w", pady=3)

        self.show_key_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Tampilkan pop up pembangkitan kunci setelah enkripsi",
                        variable=self.show_key_var).grid(row=6, column=0, columnspan=3, sticky="w", pady=3)

        btns = ttk.Frame(self)
        btns.grid(row=7, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(btns, text="Enkripsi", command=self.encrypt).pack(side="left", padx=(0, 8))
        self.key_btn = ttk.Button(btns, text="Lihat Pembangkitan Kunci",
                                  command=self.show_key_popup, state="disabled")
        self.key_btn.pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Reset", command=self.reset).pack(side="left")

        ttk.Label(self, text="Ciphertext", font=("Segoe UI", 11, "bold")).grid(
            row=8, column=0, sticky="nw", pady=(10, 3))
        self.cipher = tk.Text(self, height=3, width=60, wrap="word", state="disabled", bg="#f3f3f3")
        self.cipher.grid(row=8, column=1, columnspan=2, sticky="ew", pady=(10, 3))
        ttk.Button(self, text="Salin Ciphertext", command=self.copy_cipher).grid(
            row=9, column=1, sticky="w")

        ttk.Label(self, text="Perhitungan per blok", font=("Segoe UI", 11, "bold")).grid(
            row=10, column=0, columnspan=3, sticky="w", pady=(12, 3))
        frame, self.tree = make_table(
            self,
            [("no", "Blok"), ("teks", "Teks"), ("ascii", "ASCII (m)"), ("c", "c = m^e mod n")],
            [50, 120, 220, 220], height=6)
        frame.grid(row=11, column=0, columnspan=3, sticky="nsew")
        self.rowconfigure(11, weight=1)

    def reset(self):
        for v in (self.p_var, self.q_var, self.e_var):
            v.set("")
        self.plain.delete("1.0", "end")
        self.block_var.set(1)
        set_text(self.cipher, "")
        self.tree.delete(*self.tree.get_children())
        self.key_info = None
        self.key_btn.config(state="disabled")

    def copy_cipher(self):
        text = self.cipher.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def encrypt(self):
        try:
            p = parse_int(self.p_var.get(), "p")
            q = parse_int(self.q_var.get(), "q")
            e = parse_int(self.e_var.get(), "e")
            key = build_key(p, q, e)

            text = self.plain.get("1.0", "end-1c")
            if not text:
                raise ValueError("Plaintext tidak boleh kosong.")
            bad = [c for c in text if not (1 <= ord(c) <= 127)]
            if bad:
                raise ValueError(f"Karakter '{bad[0]}' di luar jangkauan ASCII (1-127).")

            try:
                k = int(self.block_var.get())
            except (tk.TclError, ValueError):
                raise ValueError("Ukuran blok harus berupa bilangan bulat.")
            if k < 1:
                raise ValueError("Ukuran blok minimal 1.")

            n = key["n"]
            rows, cipher_blocks = [], []
            for i in range(0, len(text), k):
                chunk = text[i:i + k]
                digits = "".join(f"{ord(c):03d}" for c in chunk)
                m = int(digits)
                if m >= n:
                    raise ValueError(
                        f"Blok ke-{i // k + 1} ('{chunk}') bernilai m = {m} ≥ n = {n}.\n"
                        "Perkecil ukuran blok atau gunakan p dan q yang lebih besar.")
                c = pow(m, e, n)
                rows.append((i // k + 1, chunk, digits, c))
                cipher_blocks.append(str(c))
        except ValueError as err:
            messagebox.showerror("Input tidak valid", str(err))
            return

        self.key_info = key
        self.key_btn.config(state="normal")
        set_text(self.cipher, " ".join(cipher_blocks))
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", values=r)
        if self.show_key_var.get():
            self.show_key_popup()

    def show_key_popup(self):
        if not self.key_info:
            return
        k = self.key_info
        win = tk.Toplevel(self)
        win.title("Pembangkitan Kunci RSA")
        win.geometry("520x470")
        win.transient(self.winfo_toplevel())
        txt = tk.Text(win, wrap="word", font=("Consolas", 10), padx=10, pady=10)
        txt.pack(fill="both", expand=True)
        lines = [
            "PEMBANGKITAN KUNCI RSA",
            "=" * 44,
            f"1. Bilangan prima      : p = {k['p']}, q = {k['q']}",
            f"2. Modulus             : n = p × q",
            f"                           = {k['p']} × {k['q']} = {k['n']}",
            f"3. Fungsi Euler        : φ(n) = (p-1)(q-1)",
            f"                           = {k['p'] - 1} × {k['q'] - 1} = {k['phi']}",
            f"4. Kunci publik e      : e = {k['e']}",
            f"   Cek gcd(e, φ(n)) = 1  ✓",
            "",
            "5. Algoritma Euclid (untuk gcd & invers):",
        ]
        lines += [f"     {s}" for s in k["steps"]]
        lines += [
            "",
            f"6. Kunci privat        : d = e⁻¹ mod φ(n) = {k['d']}",
            f"   Cek: e × d mod φ(n) = {(k['e'] * k['d']) % k['phi']}  ✓",
            "",
            "=" * 44,
            f"KUNCI PUBLIK  (e, n) = ({k['e']}, {k['n']})",
            f"KUNCI PRIVAT  (d, n) = ({k['d']}, {k['n']})",
        ]
        txt.insert("1.0", "\n".join(lines))
        txt.config(state="disabled")
        ttk.Button(win, text="Tutup", command=win.destroy).pack(pady=6)


class DecryptFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=15)
        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="Dekripsi RSA", font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.d_var, self.n_var = tk.StringVar(), tk.StringVar()
        for i, (label, var) in enumerate([("d (kunci privat)", self.d_var),
                                          ("n (modulus)", self.n_var)], start=1):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(self, textvariable=var, width=40).grid(row=i, column=1, sticky="w", pady=3)

        ttk.Label(self, text="Ciphertext\n(pisah dengan spasi)").grid(row=3, column=0, sticky="nw", pady=3)
        self.cipher = tk.Text(self, height=4, width=60, wrap="word")
        self.cipher.grid(row=3, column=1, columnspan=2, sticky="ew", pady=3)

        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(btns, text="Dekripsi", command=self.decrypt).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Reset", command=self.reset).pack(side="left")

        ttk.Label(self, text="Perhitungan per blok", font=("Segoe UI", 11, "bold")).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(8, 3))
        frame, self.tree = make_table(
            self,
            [("no", "Blok"), ("c", "Ciphertext (c)"), ("m", "m = c^d mod n"),
             ("ascii", "Kode ASCII"), ("ch", "Karakter")],
            [50, 200, 200, 150, 90], height=8)
        frame.grid(row=6, column=0, columnspan=3, sticky="nsew")
        self.rowconfigure(6, weight=1)

        ttk.Label(self, text="Pesan asli", font=("Segoe UI", 11, "bold")).grid(
            row=7, column=0, sticky="nw", pady=(12, 3))
        self.result = tk.Text(self, height=3, width=60, wrap="word", state="disabled", bg="#f3f3f3")
        self.result.grid(row=7, column=1, columnspan=2, sticky="ew", pady=(12, 3))

    def reset(self):
        self.d_var.set("")
        self.n_var.set("")
        self.cipher.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        set_text(self.result, "")

    def decrypt(self):
        try:
            d = parse_int(self.d_var.get(), "d")
            n = parse_int(self.n_var.get(), "n")
            if n < 2:
                raise ValueError("n harus lebih besar dari 1.")
            tokens = [t for t in re.split(r"[\s,;]+", self.cipher.get("1.0", "end").strip()) if t]
            if not tokens:
                raise ValueError("Ciphertext tidak boleh kosong.")
            if not all(t.isdigit() for t in tokens):
                raise ValueError("Ciphertext hanya boleh berisi angka yang dipisah spasi.")

            rows, message, warn = [], [], False
            for i, t in enumerate(tokens, start=1):
                c = int(t)
                if c >= n:
                    raise ValueError(f"Blok ke-{i}: c = {c} harus lebih kecil dari n = {n}.")
                m = pow(c, d, n)
                s = str(m)
                s = s.zfill(-(-len(s) // 3) * 3)       # lengkapi ke kelipatan 3 digit
                codes = [int(s[j:j + 3]) for j in range(0, len(s), 3)]
                chars = ""
                for code in codes:
                    if 32 <= code <= 126 or code in (9, 10, 13):
                        chars += chr(code)
                    else:
                        chars += "?"
                        warn = True
                rows.append((i, c, m, " ".join(f"{x:03d}" for x in codes), chars))
                message.append(chars)
        except ValueError as err:
            messagebox.showerror("Input tidak valid", str(err))
            return

        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", values=r)
        set_text(self.result, "".join(message))
        if warn:
            messagebox.showwarning(
                "Peringatan",
                "Ada blok yang menghasilkan kode ASCII di luar jangkauan (ditampilkan '?').\n"
                "Periksa kembali nilai d, n, atau ciphertext.")


# ----------------------------------------------------------------------
# Aplikasi utama
# ----------------------------------------------------------------------

class App(tk.Tk):
    SIDEBAR_BG = "#1f2a44"
    BTN_BG = "#2d3b5e"
    BTN_ACTIVE = "#4c6ef5"

    def __init__(self):
        super().__init__()
        self.title("Kalkulator RSA")
        self.geometry("1000x700")
        self.minsize(850, 600)
        ttk.Style(self).theme_use("clam")

        sidebar = tk.Frame(self, bg=self.SIDEBAR_BG, width=190)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="RSA", bg=self.SIDEBAR_BG, fg="white",
                 font=("Segoe UI", 20, "bold")).pack(pady=(25, 20))

        self.content = ttk.Frame(self)
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {
            "home": HomeFrame(self.content),
            "enc": EncryptFrame(self.content),
            "dec": DecryptFrame(self.content),
        }
        self.buttons = {}
        for key, label in [("home", "🏠  Beranda"), ("enc", "🔒  Enkripsi"), ("dec", "🔓  Dekripsi")]:
            b = tk.Button(sidebar, text=label, anchor="w", padx=18, pady=10, bd=0,
                          bg=self.BTN_BG, fg="white", activebackground=self.BTN_ACTIVE,
                          activeforeground="white", font=("Segoe UI", 11),
                          cursor="hand2", command=lambda k=key: self.show(k))
            b.pack(fill="x", padx=12, pady=4)
            self.buttons[key] = b

        self.show("home")

    def show(self, key):
        for page in self.pages.values():
            page.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        for k, b in self.buttons.items():
            b.config(bg=self.BTN_ACTIVE if k == key else self.BTN_BG)


if __name__ == "__main__":
    App().mainloop()
