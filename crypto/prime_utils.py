# crypto/prime_utils.py

import secrets

# Danh sách các số nguyên tố nhỏ dùng để sàng lọc nhanh (Trial Division)
# Giúp loại bỏ hơn 90% hợp số chỉ trong vài mili-giây trước khi chạy Miller-Rabin
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149
]

# ==============================================================================
# KIỂM TRA SỐ NGUYÊN TỐ MILLER-RABIN ĐÃ TỐI ƯU HÓA BẢO MẬT
# ==============================================================================

def is_prime(n, k=12):
    """
    Kiểm tra số nguyên tố bằng thuật toán Miller-Rabin kết hợp sàng lọc nhanh.
    Hỗ trợ tham số kiểm tra ngẫu nhiên bảo mật k lượt.
    """
    if n < 2:
        return False
    
    # 1. Sàng lọc nhanh bằng danh sách số nguyên tố nhỏ (Trial Division)
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 2. Phân tích n - 1 thành dạng d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # 3. Chọn tập cơ sở kiểm tra (Bases)
    if n < 341550071728321:
        # Nếu số nhỏ, dùng tập cơ sở cố định để đảm bảo chính xác tuyệt đối (Deterministic)
        bases = [2, 3, 5, 7, 11, 13, 17]
    else:
        # Nếu số lớn (Crypto), sinh ngẫu nhiên k cơ sở bảo mật bằng thư viện 'secrets'
        # Điều này chống lại hoàn toàn các cuộc tấn công tạo số giả nguyên tố cố định.
        bases = []
        while len(bases) < k:
            # Chọn ngẫu nhiên cơ sở 'a' trong khoảng [2, n - 2]
            a = secrets.randbelow(n - 3) + 2
            if a not in bases:
                bases.append(a)

    # 4. Thực hiện vòng lặp kiểm tra xác suất Miller-Rabin
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
            return False  # Chắc chắn là hợp số (Composite)

    return True  # Xác suất cao là số nguyên tố (Probable Prime)


# ==============================================================================
# SINH SỐ NGUYÊN TỐ AN TOÀN (SAFE PRIME): p = 2q + 1
# ==============================================================================

def generate_safe_prime(bits=512):
    """
    Sinh số nguyên tố an toàn bảo mật cao: p = 2q + 1 (với cả p và q đều là số nguyên tố).
    Đã được tối ưu hóa bằng 'secrets' giúp tăng tốc độ sinh và tăng tính bảo mật.
    """
    if bits < 32:
        raise ValueError("Độ dài bit quá nhỏ, tối thiểu phải từ 32-bit trở lên.")

    while True:
        # Sinh số q ngẫu nhiên bảo mật mật mã có độ dài (bits - 1)
        q = secrets.randbits(bits - 1)

        # Đảm bảo bit cao nhất (MSB) luôn là 1 và số sinh ra là số lẻ
        q |= (1 << (bits - 2)) | 1

        # Bước sàng lọc nhanh q chia cho các số nguyên tố nhỏ trước khi gọi hàm Miller-Rabin nặng
        is_q_candidate_valid = True
        for sp in SMALL_PRIMES:
            if q > sp and q % sp == 0:
                is_q_candidate_valid = False
                break
        if not is_q_candidate_valid:
            continue

        # Kiểm tra chuyên sâu cho q bằng Miller-Rabin
        if not is_prime(q, k=12):
            continue

        # Tính toán ứng viên số nguyên tố an toàn p
        p = 2 * q + 1

        # Sàng lọc nhanh cho p trước
        is_p_candidate_valid = True
        for sp in SMALL_PRIMES:
            if p > sp and p % sp == 0:
                is_p_candidate_valid = False
                break
        if not is_p_candidate_valid:
            continue

        # Kiểm tra chuyên sâu cho p bằng Miller-Rabin
        if is_prime(p, k=12):
            return p, q


# ==============================================================================
# SINH PHẦN TỬ SINH TỐI ƯU CHO SAFE PRIME O(1)
# ==============================================================================

def find_generator_safe_prime(p, q):
    """
    Tìm phần tử sinh g siêu tốc độ cho nhóm Safe Prime p = 2q + 1.
    g là phần tử sinh hợp lệ nếu: g^2 != 1 mod p và g^q != 1 mod p.
    """
    # Các ứng viên nhỏ thông dụng (thường tìm thấy phần tử sinh ngay lập tức)
    small_candidates = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]

    for g in small_candidates:
        if g >= p:
            continue
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

    # Trường hợp dự phòng an toàn (rất hiếm khi rơi vào đây)
    for g in range(2, min(p, 2000)):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g

    return None


# ==============================================================================
# OPTIONAL: SINH SỐ NGUYÊN TỐ THƯỜNG (STANDARD PRIME)
# ==============================================================================

def generate_prime(bits=256):
    """
    Sinh số nguyên tố thông thường (Không bắt buộc là Safe Prime).
    Tốc độ sinh sẽ nhanh hơn rất nhiều so với Safe Prime.
    """
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p, k=12):
            return p