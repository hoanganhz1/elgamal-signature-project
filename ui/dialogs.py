# ui/dialogs.py

from tkinter import messagebox


class Dialogs:

    @staticmethod
    def info(message, title="Thông tin"):
        """
        Hiển thị thông báo thông thường.
        """

        messagebox.showinfo(
            title,
            message
        )

    @staticmethod
    def success(message):
        """
        Hiển thị thông báo thành công.
        """

        messagebox.showinfo(
            "Thành công",
            message
        )

    @staticmethod
    def error(message):
        """
        Hiển thị thông báo lỗi.
        """

        messagebox.showerror(
            "Lỗi hệ thống",
            message
        )

    @staticmethod
    def warning(message):
        """
        Hiển thị cảnh báo.
        """

        messagebox.showwarning(
            "Cảnh báo",
            message
        )

    @staticmethod
    def confirm(message):
        """
        Hộp thoại xác nhận.

        Returns:
            True / False
        """

        return messagebox.askyesno(
            "Xác nhận",
            message
        )

    @staticmethod
    def signature_valid():
        """
        Thông báo chữ ký hợp lệ.
        """

        messagebox.showinfo(
            "Kết quả xác thực",
            "CHỮ KÝ HỢP LỆ"
        )

    @staticmethod
    def signature_invalid():
        """
        Thông báo chữ ký không hợp lệ.
        """

        messagebox.showerror(
            "Kết quả xác thực",
            "CHỮ KÝ KHÔNG HỢP LỆ"
        )
