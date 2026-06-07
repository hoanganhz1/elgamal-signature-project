# crypto/key_manager.py

import json
import os

from crypto.elgamal import ElGamalSignature


class KeyManager:

    PUBLIC_KEY_PATH = "storage/keys/public_key.json"
    PRIVATE_KEY_PATH = "storage/keys/private_key.json"

    @classmethod
    def generate_and_save_keys(cls, p, g):
        """
        Sinh cặp khóa và lưu xuống file.
        """

        public_key, private_key = ElGamalSignature.generate_keys(p, g)

        cls.save_public_key(public_key)
        cls.save_private_key(private_key)

        return public_key, private_key

    @classmethod
    def save_public_key(cls, public_key):
        """
        Lưu public key xuống file JSON.
        """

        cls._create_directories()

        with open(cls.PUBLIC_KEY_PATH, "w", encoding="utf-8") as file:
            json.dump(public_key, file, indent=4)

    @classmethod
    def save_private_key(cls, private_key):
        """
        Lưu private key xuống file JSON.
        """

        cls._create_directories()

        with open(cls.PRIVATE_KEY_PATH, "w", encoding="utf-8") as file:
            json.dump(private_key, file, indent=4)

    @classmethod
    def load_public_key(cls):
        """
        Đọc public key từ file.
        """

        if not os.path.exists(cls.PUBLIC_KEY_PATH):
            raise FileNotFoundError(
                "Không tìm thấy public_key.json"
            )

        with open(cls.PUBLIC_KEY_PATH, "r", encoding="utf-8") as file:
            return json.load(file)

    @classmethod
    def load_private_key(cls):
        """
        Đọc private key từ file.
        """

        if not os.path.exists(cls.PRIVATE_KEY_PATH):
            raise FileNotFoundError(
                "Không tìm thấy private_key.json"
            )

        with open(cls.PRIVATE_KEY_PATH, "r", encoding="utf-8") as file:
            return json.load(file)

    @classmethod
    def keys_exist(cls):
        """
        Kiểm tra đã tồn tại cặp khóa hay chưa.
        """

        return (
            os.path.exists(cls.PUBLIC_KEY_PATH)
            and
            os.path.exists(cls.PRIVATE_KEY_PATH)
        )

    @staticmethod
    def _create_directories():
        """
        Tạo thư mục nếu chưa tồn tại.
        """

        os.makedirs("storage/keys", exist_ok=True)
