# ui/main_window.py

import tkinter as tk
from tkinter import ttk, filedialog
import threading
import json

from crypto.elgamal import ElGamalSignature
from crypto.hash_utils import HashUtils
from crypto.key_manager import KeyManager
from ui.dialogs import Dialogs
from crypto.prime_utils import generate_safe_prime, find_generator_safe_prime, is_prime


# ==============================================================================
# OPTIMIZED MONKEY PATCH FOR GENERATOR VALIDATION (CHỐNG TREO THUẬT TOÁN)
# ==============================================================================

def fast_validate_generator(p, g):
    """
    Thuật toán kiểm tra phần tử sinh cải tiến, thay thế cho hàm vét cạn cũ trong elgamal.py.
    Hỗ trợ kiểm tra cực nhanh đối với cả số nguyên tố an toàn (Safe Prime) kích thước lớn.
    """
    phi = p - 1
    factors = set()
    d = phi

    # Khử nhanh các ước số nguyên tố nhỏ cơ bản
    for i in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if d % i == 0:
            factors.add(i)
            while d % i == 0:
                d //= i

    # Nếu p là Safe Prime, d lúc này chính là số nguyên tố q lớn. Kiểm tra bằng Miller-Rabin.
    if d > 1:
        if is_prime(d):
            factors.add(d)
        else:
            # Dự phòng an toàn cho số nguyên tố thường (Non-safe prime) kích thước vừa phải
            i = 33
            while i * i <= d and i < 20000:
                if d % i == 0:
                    factors.add(i)
                    while d % i == 0:
                        d //= i
                i += 2
            if d > 1:
                factors.add(d)

    # Kiểm tra điều kiện phần tử sinh thực tế
    for factor in factors:
        if pow(g, phi // factor, p) == 1:
            raise ValueError(f"g = {g} không phải là phần tử sinh hợp lệ của nhóm Z*_{p}")


# Tiến hành ghi đè hàm kiểm tra cũ để hệ thống ElGamal tự động áp dụng thuật toán mới
ElGamalSignature.validate_generator = fast_validate_generator


# ==============================================================================
# FILE MANAGEMENT HELPERS (CÁC HÀM TRỢ GIÚP TỆP TIN)
# ==============================================================================

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


# ==============================================================================
# MAIN APPLICATION WINDOW (GIAO DIỆN CHÍNH)
# ==============================================================================

class MainWindow:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hệ thống Chữ ký số ElGamal")
        self.root.geometry("1000x750")

        # 🔐 Trạng thái dữ liệu trong Runtime
        self.public_key = None
        self.private_key = None
        self.signature = None
        self.sig_data = None

        self.create_ui()

    def create_ui(self):
        # Tiêu đề ứng dụng
        tk.Label(
            self.root,
            text="HỆ THỐNG QUẢN LÝ VÀ KÝ SỐ ĐIỆN TỬ ELGAMAL",
            font=("Arial", 16, "bold"),
            fg="#1a365d"
        ).pack(pady=15)

        # Thanh điều hướng Tabs
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_key = tk.Frame(self.tabs)
        self.tab_sign = tk.Frame(self.tabs)
        self.tab_verify = tk.Frame(self.tabs)

        self.tabs.add(self.tab_key, text=" Quản lý Cặp Khóa ")
        self.tabs.add(self.tab_sign, text=" Thực hiện Ký Số ")
        self.tabs.add(self.tab_verify, text=" Xác Thực Chữ Ký ")

        self.build_key_tab()
        self.build_sign_tab()
        self.build_verify_tab()

    # ==========================================================================
    # TAB 1: QUẢN LÝ KHÓA
    # ==========================================================================
    def build_key_tab(self):
        input_frame = tk.Frame(self.tab_key)
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Độ dài Bit mong muốn (32 - 512): ", font=("Arial", 10)).grid(row=0, column=0, padx=5)
        self.bits_entry = tk.Entry(input_frame, width=12, font=("Arial", 10, "bold"), justify="center")
        self.bits_entry.insert(0, "128")
        self.bits_entry.grid(row=0, column=1, padx=5)

        btn_frame = tk.Frame(self.tab_key)
        btn_frame.pack(pady=5)

        tk.Button(
            btn_frame,
            text="🔑 Sinh Khóa Ngẫu Nhiên (RAM)",
            font=("Arial", 10, "bold"),
            bg="#2ecc71",
            fg="white",
            padx=10,
            command=self.generate_keys
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            btn_frame,
            text="💾 Xuất Khóa Công Khai (.pub)",
            font=("Arial", 10),
            bg="#3498db",
            fg="white",
            padx=10,
            command=self.save_public_key
        ).grid(row=0, column=1, padx=10)

        # Khu vực hiển thị khóa
        tk.Label(self.tab_key, text="Khóa Công Khai (Public Key):", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        self.pub_box = tk.Text(self.tab_key, height=10, font=("Consolas", 10), bg="#f8f9fa")
        self.pub_box.pack(fill="both", expand=True, padx=15, pady=2)

        tk.Label(self.tab_key, text="Khóa Bí Mật (Private Key):", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        self.priv_box = tk.Text(self.tab_key, height=8, font=("Consolas", 10), bg="#f8f9fa")
        self.priv_box.pack(fill="both", expand=True, padx=15, pady=2)

    # ==========================================================================
    # TAB 2: KÝ SỐ
    # ==========================================================================
    def build_sign_tab(self):
        action_frame = tk.Frame(self.tab_sign)
        action_frame.pack(pady=10)

        tk.Button(
            action_frame,
            text="📂 Mở tệp văn bản (.txt)",
            font=("Arial", 10),
            command=self.open_file
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            action_frame,
            text="✍️ Kiểm Tra Khóa & Ký Số (.sig)",
            font=("Arial", 10, "bold"),
            bg="#e74c3c",
            fg="white",
            command=self.sign
        ).grid(row=0, column=1, padx=10)

        tk.Label(self.tab_sign, text="Nội dung văn bản ký số:", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=2)
        self.msg_box = tk.Text(self.tab_sign, height=14, font=("Arial", 11), bg="white")
        self.msg_box.pack(fill="both", expand=True, padx=15, pady=5)

        tk.Label(self.tab_sign, text="Thông tin Chữ ký số tạo ra:", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=2)
        self.sig_box = tk.Text(self.tab_sign, height=8, font=("Consolas", 10), bg="#f8f9fa")
        self.sig_box.pack(fill="both", expand=True, padx=15, pady=5)

    # ==========================================================================
    # TAB 3: XÁC THỰC
    # ==========================================================================
    def build_verify_tab(self):
        load_frame = tk.Frame(self.tab_verify)
        load_frame.pack(pady=10)

        tk.Button(
            load_frame,
            text="📥 Tải Khóa Công Khai (.pub)",
            font=("Arial", 10),
            command=self.load_public_key
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            load_frame,
            text="📜 Tải File Chữ Ký (.sig)",
            font=("Arial", 10),
            command=self.load_signature
        ).grid(row=0, column=1, padx=10)

        tk.Label(self.tab_verify, text="Nội dung văn bản cần kiểm tra xác thực:", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=2)
        self.verify_msg = tk.Text(self.tab_verify, height=14, font=("Arial", 11), bg="white")
        self.verify_msg.pack(fill="both", expand=True, padx=15, pady=5)

        tk.Button(
            self.tab_verify,
            text="🔍 Tiến Hành Xác Thực Chữ Ký",
            font=("Arial", 11, "bold"),
            bg="#2c3e50",
            fg="white",
            pady=5,
            command=self.verify
        ).pack(pady=10)

        self.result = tk.StringVar(value="Trạng thái: Đang chờ kiểm tra...")
        result_entry = tk.Entry(
            self.tab_verify,
            textvariable=self.result,
            font=("Arial", 12, "bold"),
            justify="center",
            bd=0,
            bg="#eceff1"
        )
        result_entry.pack(fill="x", padx=15, pady=10)

    # ==========================================================================
    # LOGIC: XỬ LÝ SINH KHÓA NGẦM (THREADING)
    # ==========================================================================
    def generate_keys(self):
        try:
            bits = int(self.bits_entry.get())
            if bits < 32 or bits > 2048:
                raise ValueError("Vui lòng nhập độ dài bit trong khoảng từ 32 đến 2048.")
        except ValueError as ex:
            Dialogs.error(str(ex))
            return

        def job():
            try:
                p, q = generate_safe_prime(bits)
                g = find_generator_safe_prime(p, q)

                pub, priv = KeyManager.generate_and_save_keys(p, g)

                self.public_key = pub
                self.private_key = priv

                def ui_update():
                    self.pub_box.delete("1.0", tk.END)
                    self.priv_box.delete("1.0", tk.END)

                    self.pub_box.insert(tk.END, json.dumps(pub, indent=2))
                    self.priv_box.insert(tk.END, str(priv))
                    Dialogs.success("Sinh cặp khóa an toàn thành công và đã lưu hệ thống!")

                self.root.after(0, ui_update)
            except Exception as e:
                self.root.after(0, lambda: Dialogs.error(f"Lỗi khi tạo khóa: {str(e)}"))

        threading.Thread(target=job, daemon=True).start()

    # ==========================================================================
    # LOGIC: KIỂM TRA SNT + PHẦN TỬ SINH & KÝ SỐ NGẦM (THREADING)
    # ==========================================================================
    def sign(self):
        if not self.public_key or not self.private_key:
            Dialogs.error("Lỗi: Thiếu dữ liệu cấu hình cấu trúc khóa để ký số!")
            return

        msg = self.msg_box.get("1.0", tk.END).strip()
        if not msg:
            Dialogs.error("Lỗi: Nội dung văn bản rỗng, không thể ký số!")
            return

        def sign_job():
            try:
                p = self.public_key["p"]
                g = self.public_key["g"]

                # 1. Thực hiện kiểm tra tính toàn vẹn Số Nguyên Tố như yêu cầu
                if not is_prime(p):
                    raise ValueError("Lỗi bảo mật nghiêm trọng: Tham số 'p' trong khóa không phải là số nguyên tố!")

                # 2. Thực hiện kiểm tra tính hợp lệ của phần tử sinh g (Đã áp dụng tối ưu tránh treo)
                ElGamalSignature.validate_generator(p, g)

                # 3. Tiến hành băm SHA256 và ký số ElGamal
                h = HashUtils.sha256(msg)
                sig = ElGamalSignature.sign(h, self.private_key, self.public_key)
                self.signature = sig

                def ui_success():
                    self.sig_box.delete("1.0", tk.END)
                    self.sig_box.insert(tk.END, json.dumps(sig, indent=2))

                    # Cho phép người dùng lưu file chữ ký .sig trực tiếp
                    path = filedialog.asksaveasfilename(
                        defaultextension=".sig",
                        filetypes=[("Tệp Chữ Ký Số", "*.sig")]
                    )
                    if path:
                        export_signature(path, sig)
                        Dialogs.success("Xác thực thông số khóa an toàn & Xuất chữ ký thành công!")
                    else:
                        Dialogs.success("Đã tạo chữ ký số nội bộ thành công!")

                self.root.after(0, ui_success)
            except Exception as e:
                self.root.after(0, lambda: Dialogs.error(str(e)))

        threading.Thread(target=sign_job, daemon=True).start()

    # ==========================================================================
    # LOGIC: LƯU VÀ TẢI KHÓA/CHỮ KÝ TỪ FILE
    # ==========================================================================
    def save_public_key(self):
        if not self.public_key:
            Dialogs.error("Không có dữ liệu Khóa Công Khai để xuất!")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pub",
            filetypes=[("Khóa Công Khai ElGamal", "*.pub")]
        )
        if path:
            export_public_key(path, self.public_key)
            Dialogs.success("Đã xuất tệp Khóa Công Khai (.pub) thành công!")

    def load_public_key(self):
        path = filedialog.askopenfilename(filetypes=[("Khóa Công Khai ElGamal", "*.pub")])
        if not path:
            return

        try:
            self.public_key = import_public_key(path)
            self.pub_box.delete("1.0", tk.END)
            self.pub_box.insert(tk.END, json.dumps(self.public_key, indent=2))
            Dialogs.info("Đã tải dữ liệu Khóa Công Khai thành công!")
        except Exception as e:
            Dialogs.error(f"Tệp tin khóa lỗi hoặc sai định dạng: {str(e)}")

    def load_signature(self):
        path = filedialog.askopenfilename(filetypes=[("Tệp Chữ Ký ElGamal", "*.sig")])
        if not path:
            return

        try:
            self.sig_data = import_signature(path)
            Dialogs.info("Đã tải tệp tin chữ ký số (.sig) lên bộ nhớ!")
        except Exception as e:
            Dialogs.error(f"Tệp tin chữ ký lỗi hoặc hỏng cấu trúc JSON: {str(e)}")

    # ==========================================================================
    # LOGIC: XÁC THỰC CHỮ KÝ SỐ
    # ==========================================================================
    def verify(self):
        try:
            if not self.public_key:
                raise Exception("Chưa được cấu hình Khóa Công Khai để thực hiện kiểm tra!")

            if not self.sig_data:
                raise Exception("Thiếu tệp tin dữ liệu Chữ Ký Số cần đối sánh!")

            msg = self.verify_msg.get("1.0", tk.END).strip()
            h = HashUtils.sha256(msg)

            # Thực hiện hàm xác minh toán học của ElGamal
            ok = ElGamalSignature.verify(h, self.sig_data, self.public_key)

            if ok:
                self.result.set("KẾT QUẢ: CHỮ KÝ HỢP LỆ VÀ TOÀN VẸN (VALID)")
                Dialogs.signature_valid()
            else:
                self.result.set("KẾT QUẢ: CHỮ KÝ SAI HOẶC VĂN BẢN BỊ SỬA ĐỔI (INVALID)")
                Dialogs.signature_invalid()

        except Exception as e:
            Dialogs.error(str(e))

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Tệp văn bản", "*.txt")])
        if not path:
            return

        with open(path, "r", encoding="utf-8") as f:
            data = f.read()

        self.msg_box.delete("1.0", tk.END)
        self.msg_box.insert(tk.END, data)

    def run(self):
        self.root.mainloop()
