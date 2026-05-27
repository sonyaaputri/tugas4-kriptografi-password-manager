# Cryptographically Secure Pseudorandom Number Generator (CSPRNG)
# untuk pembangkitan password otomatis
#
# Menggunakan modul `secrets` bawaan Python, yang memanfaatkan
# os.urandom() → /dev/urandom (Linux) → kernel CSPRNG.
#
# Cara kerja:
#   1. Bangun karakter pool dari kategori yang dipilih
#      (huruf besar, kecil, angka, simbol)
#   2. Untuk setiap posisi password, bangkitkan index random
#      dengan secrets.randbelow(len(pool))
#   3. Petakan index ke karakter dari pool
#   4. Pastikan minimal 1 karakter dari setiap kategori yang dipilih
#      (untuk memenuhi persyaratan kompleksitas password)
#
# Keunggulan dibanding random.random():
#   - Menggunakan entropy dari OS (bukan PRNG deterministik)
#   - Tidak bisa diprediksi meskipun state awal diketahui
#   - Aman untuk keperluan kriptografi

import secrets
import string
from typing import List

# Karakter Pool

_UPPERCASE   = string.ascii_uppercase          # A-Z (26 chars)
_LOWERCASE   = string.ascii_lowercase          # a-z (26 chars)
_DIGITS      = string.digits                   # 0-9 (10 chars)
_SYMBOLS     = "!@#$%^&*()_+-=[]{}|;:,.<>?"   # 27 simbol umum

# Pool lengkap: semua karakter yang mungkin digunakan
_FULL_POOL   = _UPPERCASE + _LOWERCASE + _DIGITS + _SYMBOLS


# Generator Password 

def generate_password(
    length: int,
    use_uppercase : bool = True,
    use_lowercase : bool = True,
    use_digits    : bool = True,
    use_symbols   : bool = True
) -> str:
    """
    Membangkitkan password acak kriptografis dengan panjang tertentu.

    Algoritma:
    1. Bangun karakter pool dari kategori yang diaktifkan
    2. Untuk setiap slot, pilih karakter dengan secrets.randbelow()
    3. Pastikan minimal 1 karakter dari setiap kategori yang diaktifkan
       (requirement enforcement dengan Fisher-Yates shuffle)
    4. Acak ulang urutan karakter dengan secrets.SystemRandom().shuffle()

    Contoh distribusi untuk pool 90 karakter, length=16:
    - secrets.randbelow(90) → integer uniform [0, 89]
    - P(karakter tertentu) = 1/90 ≈ 1.1% per slot
    - Total kombinasi: 90^16 ≈ 1.85 × 10^31

    Parameters
    ----------
    length        : panjang password (minimal 4 jika semua kategori aktif)
    use_uppercase : sertakan huruf besar A-Z
    use_lowercase : sertakan huruf kecil a-z
    use_digits    : sertakan angka 0-9
    use_symbols   : sertakan simbol !@#$... dst

    Returns
    -------
    str : password yang dihasilkan

    Raises
    ------
    ValueError : jika tidak ada kategori yang dipilih,
                 atau length terlalu pendek untuk memenuhi persyaratan
    """
    # Validasi: minimal satu kategori harus dipilih
    selected_pools: List[str] = []
    if use_uppercase : selected_pools.append(_UPPERCASE)
    if use_lowercase : selected_pools.append(_LOWERCASE)
    if use_digits    : selected_pools.append(_DIGITS)
    if use_symbols   : selected_pools.append(_SYMBOLS)

    if not selected_pools:
        raise ValueError("Minimal satu kategori karakter harus dipilih")

    # Validasi: panjang password harus cukup untuk memuat satu karakter
    # dari setiap kategori yang dipilih
    min_length = len(selected_pools)
    if length < min_length:
        raise ValueError(
            f"Panjang password minimal {min_length} "
            f"(jumlah kategori yang dipilih)"
        )

    # Bangun pool gabungan dari semua kategori yang dipilih
    full_pool = "".join(selected_pools)

    # Langkah 1: Pastikan minimal 1 karakter dari setiap kategori
    # Menggunakan secrets.randbelow() untuk setiap pilihan
    guaranteed_chars: List[str] = []
    for pool in selected_pools:
        # Pilih 1 karakter random dari pool kategori ini
        idx = secrets.randbelow(len(pool))
        guaranteed_chars.append(pool[idx])

    # Langkah 2: Isi sisa slot dengan karakter dari pool gabungan
    remaining_length = length - len(guaranteed_chars)
    random_chars: List[str] = []
    for _ in range(remaining_length):
        idx = secrets.randbelow(len(full_pool))
        random_chars.append(full_pool[idx])

    # Gabungkan semua karakter
    all_chars = guaranteed_chars + random_chars

    # Langkah 3: Acak ulang urutan dengan Fisher-Yates shuffle
    # menggunakan SystemRandom (berbasis os.urandom)
    sys_random = secrets.SystemRandom()
    sys_random.shuffle(all_chars)

    return "".join(all_chars)


def generate_password_interactive() -> str:
    """
    Antarmuka interaktif CLI untuk membangkitkan password.
    Meminta input dari pengguna untuk panjang dan kategori karakter.

    Returns
    -------
    str : password yang dihasilkan
    """
    print("\n─── Pembangkit Password Otomatis ───")

    # Input panjang password
    while True:
        try:
            length = int(input("Panjang password (8-128): ").strip())
            if 8 <= length <= 128:
                break
            print("Panjang harus antara 8 dan 128.")
        except ValueError:
            print("Masukkan angka yang valid.")

    # Input kategori karakter
    print("Pilih kategori karakter (tekan Enter untuk default semua):")
    use_uppercase = input("  Huruf besar A-Z? [Y/n]: ").strip().lower() != "n"
    use_lowercase = input("  Huruf kecil a-z? [Y/n]: ").strip().lower() != "n"
    use_digits    = input("  Angka 0-9?       [Y/n]: ").strip().lower() != "n"
    use_symbols   = input("  Simbol !@#$...?  [Y/n]: ").strip().lower() != "n"

    # Generate password
    try:
        password = generate_password(
            length        = length,
            use_uppercase = use_uppercase,
            use_lowercase = use_lowercase,
            use_digits    = use_digits,
            use_symbols   = use_symbols,
        )
        print(f"\nPassword yang dibangkitkan: {password}")
        return password
    except ValueError as e:
        print(f"Error: {e}")
        return generate_password_interactive()