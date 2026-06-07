# storage/signature_manager.py

import json
import os


class SignatureManager:

    FILE_PATH = (
        "storage/signatures/signature.json"
    )

    @classmethod
    def save_signature(
        cls,
        message,
        signature
    ):

        os.makedirs(
            "storage/signatures",
            exist_ok=True
        )

        data = {
            "message": message,
            "r": signature["r"],
            "s": signature["s"]
        }

        with open(
            cls.FILE_PATH,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )

    @classmethod
    def load_signature(cls):

        with open(
            cls.FILE_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)
