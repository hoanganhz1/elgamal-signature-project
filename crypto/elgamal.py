# crypto/elgamal.py

import secrets
from math import gcd

from crypto.prime_utils import (
    is_prime,
    find_generator_safe_prime
)


class ElGamalSignature:

    @staticmethod
    def mod_inverse(a, m):

        def extended_gcd(a, b):

            if a == 0:
                return b, 0, 1

            g, x1, y1 = extended_gcd(b % a, a)

            x = y1 - (b // a) * x1
            y = x1

            return g, x, y

        g, x, _ = extended_gcd(a, m)

        if g != 1:
            raise ValueError("Không tồn tại nghịch đảo modulo")

        return x % m

    # ==========================================
    # VALIDATION
    # ==========================================

    @staticmethod
    def validate_prime(p):

        if not is_prime(p):
            raise ValueError("p không phải số nguyên tố")

    @staticmethod
    def validate_generator(p, g):

        phi = p - 1

        factors = set()

        d = phi
        i = 2

        while i * i <= d:

            if d % i == 0:

                factors.add(i)

                while d % i == 0:
                    d //= i

            i += 1

        if d > 1:
            factors.add(d)

        for factor in factors:

            if pow(g, phi // factor, p) == 1:
                raise ValueError(
                    f"g = {g} không phải phần tử sinh của Z*_{p}"
                )

    @staticmethod
    def validate_public_key(public_key):

        required = {"p", "g", "y"}

        if not required.issubset(public_key):
            raise ValueError("Public key không hợp lệ")

        p = public_key["p"]
        g = public_key["g"]
        y = public_key["y"]

        ElGamalSignature.validate_prime(p)
        ElGamalSignature.validate_generator(p, g)

        if not (1 < y < p):
            raise ValueError("y không hợp lệ")

    @staticmethod
    def validate_private_key(private_key, p):

        if "x" not in private_key:
            raise ValueError("Private key không hợp lệ")

        x = private_key["x"]

        if not (1 < x < p - 1):
            raise ValueError("x không hợp lệ")

    # ==========================================
    # KEY GENERATION
    # ==========================================

    @staticmethod
    def generate_keys(p, g):

        ElGamalSignature.validate_prime(p)
        ElGamalSignature.validate_generator(p, g)

        x = secrets.randbelow(p - 3) + 2

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

    # ==========================================
    # SIGN
    # ==========================================

    @staticmethod
    def sign(message_hash, private_key, public_key):

        ElGamalSignature.validate_public_key(public_key)

        p = public_key["p"]
        g = public_key["g"]

        ElGamalSignature.validate_private_key(
            private_key,
            p
        )

        x = private_key["x"]

        while True:

            k = secrets.randbelow(p - 3) + 2

            if gcd(k, p - 1) != 1:
                continue

            r = pow(g, k, p)

            if r == 0:
                continue

            k_inv = ElGamalSignature.mod_inverse(
                k,
                p - 1
            )

            s = (
                k_inv *
                (message_hash - x * r)
            ) % (p - 1)

            if s == 0:
                continue

            return {
                "r": r,
                "s": s
            }

    # ==========================================
    # VERIFY
    # ==========================================

    @staticmethod
    def verify(message_hash, signature, public_key):

        try:

            ElGamalSignature.validate_public_key(
                public_key
            )

            p = public_key["p"]
            g = public_key["g"]
            y = public_key["y"]

            if "r" not in signature:
                return False

            if "s" not in signature:
                return False

            r = signature["r"]
            s = signature["s"]

            if not (1 <= r <= p - 1):
                return False

            if not (0 <= s <= p - 2):
                return False

            left = (
                pow(y, r, p) *
                pow(r, s, p)
            ) % p

            right = pow(
                g,
                message_hash,
                p
            )

            return left == right

        except Exception:
            return False