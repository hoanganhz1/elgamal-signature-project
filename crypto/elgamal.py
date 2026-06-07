# crypto/elgamal.py

import random
from math import gcd


class ElGamalSignature:
    """
    ElGamal Digital Signature
    """

    @staticmethod
    def mod_inverse(a, m):
        """
        Tính nghịch đảo modulo bằng Extended Euclidean Algorithm
        """

        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1

            g, x1, y1 = extended_gcd(b % a, a)

            x = y1 - (b // a) * x1
            y = x1

            return g, x, y

        g, x, _ = extended_gcd(a, m)

        if g != 1:
            raise Exception("Modular inverse does not exist")

        return x % m

    @staticmethod
    def generate_keys(p, g):
        """
        Sinh khóa ElGamal

        Parameters:
            p : số nguyên tố
            g : phần tử sinh

        Returns:
            public_key
            private_key
        """

        x = random.randint(2, p - 2)

        y = pow(g, x, p)

        public_key = {
            "p": p,
            "g": g,
            "y": y
        }

        private_key = {
            "x": x
        }

        return public_key, private_key

    @staticmethod
    def sign(message_hash, private_key, public_key):
        """
        Ký số

        Parameters:
            message_hash : hash của văn bản (int)
            private_key
            public_key

        Returns:
            (r, s)
        """

        p = public_key["p"]
        g = public_key["g"]
        x = private_key["x"]

        while True:

            k = random.randint(2, p - 2)

            if gcd(k, p - 1) == 1:
                break

        r = pow(g, k, p)

        k_inv = ElGamalSignature.mod_inverse(k, p - 1)

        s = (k_inv * (message_hash - x * r)) % (p - 1)

        return {
            "r": r,
            "s": s
        }

    @staticmethod
    def verify(message_hash, signature, public_key):
        """
        Xác thực chữ ký

        Parameters:
            message_hash : hash của văn bản
            signature : {"r":..., "s":...}
            public_key

        Returns:
            True / False
        """

        p = public_key["p"]
        g = public_key["g"]
        y = public_key["y"]

        r = signature["r"]
        s = signature["s"]

        if r <= 0 or r >= p:
            return False

        left = (
            pow(y, r, p) *
            pow(r, s, p)
        ) % p

        right = pow(g, message_hash, p)

        return left == right