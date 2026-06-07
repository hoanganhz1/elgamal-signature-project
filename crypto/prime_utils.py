import random


# ==================================================
# MILLER-RABIN PRIMALITY TEST (FAST + RELIABLE)
# ==================================================

def is_prime(n, k=12):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # n - 1 = d * 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # deterministic small bases (fast + good accuracy for crypto demo)
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23]

    for a in bases:
        if a >= n:
            continue

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


# ==================================================
# SAFE PRIME GENERATION: p = 2q + 1
# ==================================================

def generate_safe_prime(bits=512):
    """
    Sinh safe prime:
        p = 2q + 1
        q cũng là prime

    Ưu điểm:
        - generator nhanh O(1)
        - dùng tốt cho ElGamal / DH
        - scale 512–2048 bits
    """

    if bits < 32:
        raise ValueError("Bit size too small (min 32)")

    while True:

        # sinh q trước
        q = random.getrandbits(bits - 1)

        # đảm bảo bit cao + số lẻ
        q |= (1 << (bits - 2)) | 1

        if not is_prime(q):
            continue

        p = 2 * q + 1

        if is_prime(p):
            return p, q


# ==================================================
# FAST GENERATOR FOR SAFE PRIME
# ==================================================

def find_generator_safe_prime(p, q):
    """
    O(1) generator search:
    Với p = 2q + 1:

    g là generator nếu:
        g^2 != 1 mod p
        g^q != 1 mod p
    """

    # thử nhanh các giá trị nhỏ (thường đủ)
    small_candidates = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]

    for g in small_candidates:
        if g >= p:
            continue
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

    # fallback nhẹ (rất hiếm khi dùng)
    for g in range(2, min(p, 2000)):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

    return None


# ==================================================
# OPTIONAL: STANDARD PRIME (NON SAFE PRIME)
# ==================================================

def generate_prime(bits=256):
    """
    Prime thường (không dùng safe prime).
    Chỉ dùng nếu không cần generator tối ưu.
    """

    while True:
        p = random.getrandbits(bits)

        # set MSB + ensure odd
        p |= (1 << (bits - 1)) | 1

        if is_prime(p):
            return p


# ==================================================
# OPTIONAL: OLD BRUTE FORCE GENERATOR (NOT RECOMMENDED)
# ==================================================

def find_primitive_root(p):
    """
    Bản cũ O(p) → không dùng cho bit lớn.
    Giữ lại để debug.
    """

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

    for g in range(2, p):
        ok = True
        for f in factors:
            if pow(g, phi // f, p) == 1:
                ok = False
                break
        if ok:
            return g

    return None