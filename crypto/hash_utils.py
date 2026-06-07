import hashlib


class HashUtils:

    @staticmethod
    def sha256(message: str) -> int:
        """
        Băm chuỗi bằng SHA-256 và trả về số nguyên.

        Parameters:
            message (str): Nội dung văn bản

        Returns:
            int: Giá trị hash dạng số nguyên
        """

        hash_hex = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        return int(hash_hex, 16)

    @staticmethod
    def sha256_file(file_path: str) -> int:
        """
        Băm nội dung file bằng SHA-256.

        Parameters:
            file_path (str): Đường dẫn file

        Returns:
            int: Giá trị hash dạng số nguyên
        """

        sha = hashlib.sha256()

        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha.update(chunk)

        return int(sha.hexdigest(), 16)

    @staticmethod
    def sha256_hex(message: str) -> str:
        """
        Trả về SHA-256 dạng chuỗi hex.

        Parameters:
            message (str)

        Returns:
            str
        """

        return hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()