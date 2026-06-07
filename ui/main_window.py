import tkinter as tk
from tkinter import ttk, filedialog, Menu
import threading
import json

from crypto.elgamal import ElGamalSignature
from crypto.hash_utils import HashUtils
from crypto.key_manager import KeyManager
from ui.dialogs import Dialogs
from crypto.prime_utils import generate_safe_prime, find_generator_safe_prime


# =========================
# FILE HELPERS
# =========================

def export_signature(path, sig):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "r": sig["r"],
            "s": sig["s"],
            "algo": "ElGamal",
            "hash": "SHA256"
        }, f, indent=4)


def import_signature(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def export_public_key(path, pub):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pub, f, indent=4)


def import_public_key(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =========================
# MAIN WINDOW
# =========================

class MainWindow:

    def __init__(self):

        self.root = tk.Tk()
        self.root.title("ElGamal Digital Signature PRO MAX")
        self.root.geometry("1000x750")

        # 🔐 runtime state
        self.public_key = None
        self.private_key = None
        self.signature = None
        self.sig_data = None

        self.create_ui()

    # ================= UI =================

    def create_ui(self):

        tk.Label(
            self.root,
            text="ELGAMAL DIGITAL SIGNATURE SYSTEM",
            font=("Arial", 18, "bold")
        ).pack(pady=10)

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True)

        self.tab_key = tk.Frame(self.tabs)
        self.tab_sign = tk.Frame(self.tabs)
        self.tab_verify = tk.Frame(self.tabs)

        self.tabs.add(self.tab_key, text="Key")
        self.tabs.add(self.tab_sign, text="Sign")
        self.tabs.add(self.tab_verify, text="Verify")

        self.build_key_tab()
        self.build_sign_tab()
        self.build_verify_tab()

    # ================= KEY TAB =================

    def build_key_tab(self):

        tk.Label(self.tab_key, text="Bit size").pack()

        self.bits_entry = tk.Entry(self.tab_key)
        self.bits_entry.insert(0, "128")
        self.bits_entry.pack()

        tk.Button(
            self.tab_key,
            text="Generate Key (RAM)",
            command=self.generate_keys
        ).pack(pady=5)

        tk.Button(
            self.tab_key,
            text="Export Public Key (.pub)",
            command=self.save_public_key
        ).pack()

        tk.Label(self.tab_key, text="Public Key").pack()
        self.pub_box = tk.Text(self.tab_key, height=8)
        self.pub_box.pack(fill="both")

        tk.Label(self.tab_key, text="Private Key").pack()
        self.priv_box = tk.Text(self.tab_key, height=6)
        self.priv_box.pack(fill="both")

    # ================= SIGN TAB =================

    def build_sign_tab(self):

        tk.Button(self.tab_sign, text="Open TXT", command=self.open_file).pack()
        tk.Button(self.tab_sign, text="Sign + Export .sig", command=self.sign).pack()

        self.msg_box = tk.Text(self.tab_sign, height=12)
        self.msg_box.pack(fill="both")

        self.sig_box = tk.Text(self.tab_sign, height=6)
        self.sig_box.pack(fill="both")

    # ================= VERIFY TAB =================

    def build_verify_tab(self):

        tk.Button(
            self.tab_verify,
            text="Load Public Key (.pub)",
            command=self.load_public_key
        ).pack()

        tk.Button(
            self.tab_verify,
            text="Load Signature (.sig)",
            command=self.load_signature
        ).pack()

        tk.Label(self.tab_verify, text="Message").pack()

        self.verify_msg = tk.Text(self.tab_verify, height=10)
        self.verify_msg.pack(fill="both")

        tk.Button(
            self.tab_verify,
            text="Verify",
            command=self.verify
        ).pack()

        self.result = tk.StringVar()
        tk.Entry(self.tab_verify, textvariable=self.result).pack(fill="x")

    # ================= KEY GEN =================

    def generate_keys(self):

        bits = int(self.bits_entry.get())

        def job():

            p, q = generate_safe_prime(bits)
            g = find_generator_safe_prime(p, q)

            pub, priv = KeyManager.generate_and_save_keys(p, g)

            self.public_key = pub
            self.private_key = priv

            def ui():
                self.pub_box.delete("1.0", tk.END)
                self.priv_box.delete("1.0", tk.END)

                self.pub_box.insert(tk.END, json.dumps(pub, indent=2))
                self.priv_box.insert(tk.END, str(priv))

                Dialogs.success("Keys generated")

            self.root.after(0, ui)

        threading.Thread(target=job, daemon=True).start()

    # ================= SAVE PUBLIC KEY =================

    def save_public_key(self):

        if not self.public_key:
            Dialogs.error("No public key")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pub",
            filetypes=[("Public Key", "*.pub")]
        )

        if path:
            export_public_key(path, self.public_key)
            Dialogs.success("Public key exported")

    # ================= LOAD PUBLIC KEY =================

    def load_public_key(self):

        path = filedialog.askopenfilename(filetypes=[("Public Key", "*.pub")])
        if not path:
            return

        self.public_key = import_public_key(path)

        self.pub_box.delete("1.0", tk.END)
        self.pub_box.insert(tk.END, json.dumps(self.public_key, indent=2))

        Dialogs.info("Public key loaded")

    # ================= SIGN =================

    def sign(self):

        if not self.public_key or not self.private_key:
            Dialogs.error("Missing key")
            return

        msg = self.msg_box.get("1.0", tk.END).strip()

        h = HashUtils.sha256(msg)

        sig = ElGamalSignature.sign(h, self.private_key, self.public_key)

        self.signature = sig

        path = filedialog.asksaveasfilename(
            defaultextension=".sig",
            filetypes=[("Signature", "*.sig")]
        )

        if path:
            export_signature(path, sig)

        self.sig_box.delete("1.0", tk.END)
        self.sig_box.insert(tk.END, json.dumps(sig, indent=2))

        Dialogs.success("Signed & exported")

    # ================= LOAD SIGNATURE =================

    def load_signature(self):

        path = filedialog.askopenfilename(filetypes=[("Signature", "*.sig")])
        if not path:
            return

        self.sig_data = import_signature(path)

        Dialogs.info("Signature loaded")

    # ================= VERIFY =================

    def verify(self):

        try:
            if not self.public_key:
                raise Exception("No public key loaded")

            if not self.sig_data:
                raise Exception("No signature loaded")

            msg = self.verify_msg.get("1.0", tk.END).strip()

            h = HashUtils.sha256(msg)

            ok = ElGamalSignature.verify(
                h,
                self.sig_data,
                self.public_key
            )

            self.result.set("VALID" if ok else "INVALID")

        except Exception as e:
            Dialogs.error(str(e))

    # ================= OPEN FILE =================

    def open_file(self):

        path = filedialog.askopenfilename(filetypes=[("TXT", "*.txt")])
        if not path:
            return

        with open(path, "r", encoding="utf-8") as f:
            data = f.read()

        self.msg_box.delete("1.0", tk.END)
        self.msg_box.insert(tk.END, data)

    # ================= RUN =================

    def run(self):
        self.root.mainloop()