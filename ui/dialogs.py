# ui/dialogs.py

from tkinter import messagebox


class Dialogs:

    @staticmethod
    def info(message, title="Information"):
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
            "Success",
            message
        )

    @staticmethod
    def error(message):
        """
        Hiển thị thông báo lỗi.
        """

        messagebox.showerror(
            "Error",
            message
        )

    @staticmethod
    def warning(message):
        """
        Hiển thị cảnh báo.
        """

        messagebox.showwarning(
            "Warning",
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
            "Confirmation",
            message
        )

    @staticmethod
    def signature_valid():
        """
        Thông báo chữ ký hợp lệ.
        """

        messagebox.showinfo(
            "Verification",
            "VALID SIGNATURE"
        )

    @staticmethod
    def signature_invalid():
        """
        Thông báo chữ ký không hợp lệ.
        """

        messagebox.showerror(
            "Verification",
            "INVALID SIGNATURE"
        )
