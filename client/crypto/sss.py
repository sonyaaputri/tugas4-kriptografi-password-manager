# Implementasi Shamir Secret Sharing (SSS)
#
# Menggunakan skema ambang batas (threshold, total) di atas
# finite field GF(p) dengan p = bilangan prima besar.
#
# Ide dasar:
#   - Secret s direpresentasikan sebagai koefisien bebas polinomial
#     f(x) = s + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)  (mod p)
#   - Share ke-i adalah pasangan (i, f(i))
#   - Rekonstruksi secret dengan Lagrange interpolation dari
#     minimal t share: f(0) = secret


import secrets
import json
from typing import List, Dict

# Konstanta

# Bilangan prima besar 256-bit untuk GF(p).
# Harus lebih besar dari nilai maksimum secret (256-bit / 32 bytes).
# Nilai ini umum dipakai sebagai modulus field secp256k1.
_PRIME = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
)

# Ukuran secret dalam bytes (harus < PRIME)
# AES-128 → 16 bytes; master key 16 bytes aman di bawah PRIME 256-bit
_MAX_SECRET_BYTES = 32


# Aritmetika Modular

def _mod_inverse(a: int, p: int) -> int:
    """
    Menghitung invers modular a^(-1) mod p menggunakan
    algoritma Extended Euclidean.

    Digunakan dalam Lagrange interpolation untuk pembagian modular.

    Parameters
    ----------
    a : bilangan yang akan dicari inversnya
    p : modulus (bilangan prima)

    Returns
    -------
    int : a^(-1) mod p
    """
    # Algoritma Extended Euclidean
    old_r, r = a % p, p
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    # old_r = gcd(a, p); untuk prima p, gcd = 1 selalu
    return old_s % p


def _eval_polynomial(coefficients: List[int], x: int, prime: int) -> int:
    """
    Evaluasi polinomial f(x) = c0 + c1*x + c2*x^2 + ... (mod prime)
    menggunakan Horner's method untuk efisiensi.

    Parameters
    ----------
    coefficients : list koefisien [c0=secret, c1, c2, ...]
    x            : nilai x (index share)
    prime        : modulus

    Returns
    -------
    int : f(x) mod prime
    """
    result = 0
    # Horner's method: evaluasi dari koefisien tertinggi
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % prime
    return result


# Generate Shares

def generate_shares(
    secret: bytes,
    threshold: int,
    total: int
) -> List[Dict]:
    """
    Membagi secret menjadi 'total' share dengan skema ambang batas
    (threshold, total).

    Minimal 'threshold' share diperlukan untuk rekonstruksi.
    Kurang dari 'threshold' share tidak membocorkan informasi
    apapun tentang secret (information-theoretic security).

    Parameters
    ----------
    secret    : secret yang akan dibagi (bytes, maks 32 bytes)
    threshold : jumlah minimal share untuk rekonstruksi
    total     : jumlah total share yang dibuat

    Returns
    -------
    List of dict, masing-masing berisi:
    {
        "index": int,   # koordinat x pada polinomial (1-based)
        "value": str    # f(index) dalam format hex string
    }

    Raises
    ------
    ValueError : jika parameter tidak valid

    Contoh
    ------
    shares = generate_shares(master_key, threshold=2, total=3)
    # returns:
    # [
    #   {"index": 1, "value": "a1b2c3..."},  # local share
    #   {"index": 2, "value": "d4e5f6..."},  # server share
    #   {"index": 3, "value": "789abc..."},  # recovery share
    # ]
    """
    # Validasi parameter
    if threshold < 2:
        raise ValueError("Threshold minimal 2")
    if total < threshold:
        raise ValueError("Total share harus >= threshold")
    if len(secret) > _MAX_SECRET_BYTES:
        raise ValueError(f"Secret maksimal {_MAX_SECRET_BYTES} bytes")

    # Konversi secret bytes ke integer
    secret_int = int.from_bytes(secret, byteorder="big")

    if secret_int >= _PRIME:
        raise ValueError("Nilai secret melebihi prime modulus")

    # Bangun polinomial random berderajat (threshold - 1):
    # f(x) = secret + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)  (mod p)
    # Koefisien a1..a(t-1) dipilih secara random di [1, PRIME-1]
    coefficients = [secret_int]
    for _ in range(threshold - 1):
        rand_coeff = secrets.randbelow(_PRIME - 1) + 1  # hindari 0
        coefficients.append(rand_coeff)

    # Hitung share: (i, f(i)) untuk i = 1..total
    shares = []
    for i in range(1, total + 1):
        y = _eval_polynomial(coefficients, i, _PRIME)
        # Konversi nilai y ke hex string (32 bytes / 64 hex chars)
        y_hex = format(y, "064x")
        shares.append({"index": i, "value": y_hex})

    return shares


# Reconstruct Secret

def reconstruct_secret(shares: List[Dict]) -> bytes:
    """
    Merekonstruksi secret dari minimal 'threshold' share menggunakan
    Lagrange interpolation di GF(PRIME).

    f(0) = Σ [ y_i * Π_{j≠i} (0 - x_j) / (x_i - x_j) ]  (mod p)

    Parameters
    ----------
    shares : list of dict minimal 2 share, format:
             [{"index": int, "value": hex_str}, ...]
             Share dapat berupa kombinasi manapun dari
             (local, server, recovery) share.

    Returns
    -------
    bytes : secret yang berhasil direkonstruksi (16 bytes untuk AES-128)

    Raises
    ------
    ValueError : jika share tidak valid atau jumlah share kurang

    Catatan
    -------
    Jika share yang diberikan salah (misalnya recovery share dari
    vault yang berbeda), hasil rekonstruksi akan berbeda dari
    master key asli → dekripsi vault akan gagal (AES-GCM auth tag).
    Tidak ada informasi error yang bocor tentang share yang benar.
    """
    if len(shares) < 2:
        raise ValueError("Minimal 2 share diperlukan untuk rekonstruksi")

    # Parse shares: ambil pasangan (x, y) sebagai integer
    points = []
    for share in shares:
        if "index" not in share or "value" not in share:
            raise ValueError(f"Format share tidak valid: {share}")
        x = int(share["index"])
        y = int(share["value"], 16)  # hex → int
        if x < 1:
            raise ValueError(f"Index share harus >= 1, dapat: {x}")
        points.append((x, y))

    # Pastikan tidak ada index duplikat
    indices = [p[0] for p in points]
    if len(set(indices)) != len(indices):
        raise ValueError("Terdapat share dengan index yang sama")

    # Lagrange interpolation di x=0 untuk dapatkan f(0) = secret
    secret_int = 0
    for i, (x_i, y_i) in enumerate(points):
        # Hitung Lagrange basis polynomial L_i(0):
        # L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)  (mod p)
        numerator   = 1
        denominator = 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            # (0 - x_j) = -x_j ≡ PRIME - x_j (mod PRIME)
            numerator   = (numerator * (0 - x_j)) % _PRIME
            denominator = (denominator * (x_i - x_j)) % _PRIME

        # L_i(0) = numerator * denominator^(-1) (mod PRIME)
        lagrange_coeff = (numerator * _mod_inverse(denominator, _PRIME)) % _PRIME

        # Akumulasi: secret += y_i * L_i(0)
        secret_int = (secret_int + y_i * lagrange_coeff) % _PRIME

    # Konversi integer ke bytes (16 bytes untuk AES-128 master key)
    # Gunakan 32 bytes sebagai ukuran maksimum, lalu slice ke 16 bytes
    secret_bytes = secret_int.to_bytes(32, byteorder="big")

    # Potong ke 16 bytes (128-bit) untuk master key AES-128
    return secret_bytes[-16:]


# Serialisasi Share

def share_to_string(share: Dict) -> str:
    """
    Mengkonversi share ke format string yang bisa disimpan/ditampilkan.
    Format: "SSS:index:value_hex"

    Digunakan untuk menampilkan recovery share ke pengguna.

    Parameters
    ----------
    share : dict {"index": int, "value": hex_str}

    Returns
    -------
    str : "SSS:{index}:{value}"

    Contoh
    ------
    "SSS:3:a1b2c3d4e5f6..."
    """
    return f"SSS:{share['index']}:{share['value']}"


def string_to_share(share_str: str) -> Dict:
    """
    Mengkonversi string share kembali ke dict.
    Kebalikan dari share_to_string().

    Parameters
    ----------
    share_str : string format "SSS:{index}:{value}"

    Returns
    -------
    dict {"index": int, "value": hex_str}

    Raises
    ------
    ValueError : jika format string tidak valid
    """
    parts = share_str.strip().split(":")
    if len(parts) != 3 or parts[0] != "SSS":
        raise ValueError(
            f"Format share tidak valid: '{share_str}'\n"
            f"Format yang benar: 'SSS:{{index}}:{{value_hex}}'"
        )
    try:
        index = int(parts[1])
        value = parts[2]
        # Validasi value adalah hex string yang valid
        int(value, 16)
        return {"index": index, "value": value}
    except ValueError as e:
        raise ValueError(f"Share tidak valid: {e}")
