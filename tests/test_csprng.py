# Unit Test untuk client/crypto/csprng.py
#
# Menguji:
#   1. Panjang password sesuai yang diminta
#   2. Setiap kategori karakter yang dipilih terwakili
#   3. Password berbeda setiap kali dipanggil (randomness)
#   4. Hanya karakter dari pool yang dipilih yang muncul
#   5. Error jika tidak ada kategori dipilih
#   6. Error jika panjang terlalu pendek

import sys
import os
import unittest
import string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client", "crypto"))

from crypto.csprng import generate_password


_UPPERCASE = string.ascii_uppercase
_LOWERCASE = string.ascii_lowercase
_DIGITS    = string.digits
_SYMBOLS   = "!@#$%^&*()_+-=[]{}|;:,.<>?"


class TestPasswordLength(unittest.TestCase):

    def test_length_8(self):
        pwd = generate_password(8)
        self.assertEqual(len(pwd), 8)

    def test_length_16(self):
        pwd = generate_password(16)
        self.assertEqual(len(pwd), 16)

    def test_length_32(self):
        pwd = generate_password(32)
        self.assertEqual(len(pwd), 32)

    def test_length_64(self):
        pwd = generate_password(64)
        self.assertEqual(len(pwd), 64)

    def test_length_128(self):
        pwd = generate_password(128)
        self.assertEqual(len(pwd), 128)

    def test_minimum_length_all_categories(self):
        """Panjang minimal 4 jika semua kategori aktif."""
        pwd = generate_password(4)
        self.assertEqual(len(pwd), 4)

    def test_minimum_length_one_category(self):
        """Panjang minimal 1 jika hanya satu kategori aktif."""
        pwd = generate_password(
            1,
            use_uppercase=True,
            use_lowercase=False,
            use_digits=False,
            use_symbols=False
        )
        self.assertEqual(len(pwd), 1)


class TestPasswordCharacterCategories(unittest.TestCase):
    """Uji kehadiran karakter dari setiap kategori yang dipilih."""

    def test_all_categories_present(self):
        """Password dengan semua kategori harus memiliki minimal 1 dari tiap kategori."""
        # Uji beberapa kali untuk mengurangi peluang false positive
        for _ in range(10):
            pwd = generate_password(20)
            has_upper  = any(c in _UPPERCASE for c in pwd)
            has_lower  = any(c in _LOWERCASE for c in pwd)
            has_digit  = any(c in _DIGITS    for c in pwd)
            has_symbol = any(c in _SYMBOLS   for c in pwd)
            self.assertTrue(has_upper,  f"Tidak ada huruf besar di: {pwd}")
            self.assertTrue(has_lower,  f"Tidak ada huruf kecil di: {pwd}")
            self.assertTrue(has_digit,  f"Tidak ada angka di: {pwd}")
            self.assertTrue(has_symbol, f"Tidak ada simbol di: {pwd}")

    def test_only_uppercase(self):
        """Password hanya dari huruf besar."""
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=True,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False
            )
            self.assertTrue(all(c in _UPPERCASE for c in pwd),
                            f"Ada karakter non-uppercase di: {pwd}")

    def test_only_lowercase(self):
        """Password hanya dari huruf kecil."""
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=False,
                use_lowercase=True,
                use_digits=False,
                use_symbols=False
            )
            self.assertTrue(all(c in _LOWERCASE for c in pwd),
                            f"Ada karakter non-lowercase di: {pwd}")

    def test_only_digits(self):
        """Password hanya dari angka."""
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=True,
                use_symbols=False
            )
            self.assertTrue(all(c in _DIGITS for c in pwd),
                            f"Ada karakter non-digit di: {pwd}")

    def test_only_symbols(self):
        """Password hanya dari simbol."""
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=True
            )
            self.assertTrue(all(c in _SYMBOLS for c in pwd),
                            f"Ada karakter non-simbol di: {pwd}")

    def test_uppercase_and_digits(self):
        """Password dari huruf besar dan angka saja."""
        allowed = set(_UPPERCASE + _DIGITS)
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=True,
                use_lowercase=False,
                use_digits=True,
                use_symbols=False
            )
            self.assertTrue(all(c in allowed for c in pwd),
                            f"Ada karakter di luar pool di: {pwd}")
            self.assertTrue(any(c in _UPPERCASE for c in pwd))
            self.assertTrue(any(c in _DIGITS    for c in pwd))

    def test_lowercase_and_digits(self):
        """Password dari huruf kecil dan angka saja."""
        allowed = set(_LOWERCASE + _DIGITS)
        for _ in range(5):
            pwd = generate_password(
                20,
                use_uppercase=False,
                use_lowercase=True,
                use_digits=True,
                use_symbols=False
            )
            self.assertTrue(all(c in allowed for c in pwd))


class TestPasswordRandomness(unittest.TestCase):
    """Uji sifat acak password (tidak deterministik)."""

    def test_two_passwords_different(self):
        """Dua pemanggilan menghasilkan password berbeda."""
        pwd1 = generate_password(32)
        pwd2 = generate_password(32)
 
        self.assertNotEqual(pwd1, pwd2,
                            "Dua password identik terdeteksi — kemungkinan ada masalah CSPRNG!")

    def test_ten_passwords_all_different(self):
        """10 pemanggilan menghasilkan 10 password yang semuanya unik."""
        passwords = {generate_password(24) for _ in range(10)}
        self.assertEqual(len(passwords), 10,
                         "Ada password duplikat dalam 10 generate — kemungkinan ada masalah CSPRNG!")

    def test_passwords_are_strings(self):
        """generate_password mengembalikan string."""
        pwd = generate_password(16)
        self.assertIsInstance(pwd, str)

    def test_no_null_bytes(self):
        """Password tidak mengandung null byte."""
        for _ in range(5):
            pwd = generate_password(32)
            self.assertNotIn('\x00', pwd)


class TestPasswordValidationErrors(unittest.TestCase):
    """Uji kondisi error yang harus dilempar."""

    def test_no_category_raises_value_error(self):
        """Tidak ada kategori yang dipilih harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                16,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False
            )

    def test_length_too_short_all_categories_raises_value_error(self):
        """Panjang 3 saat semua 4 kategori aktif harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                3,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_symbols=True
            )

    def test_length_too_short_two_categories_raises_value_error(self):
        """Panjang 1 saat 2 kategori aktif harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                1,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=False,
                use_symbols=False
            )

    def test_length_zero_raises_value_error(self):
        """Panjang 0 harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(0)


class TestPasswordStrength(unittest.TestCase):
    """Uji kekuatan statistik password yang dihasilkan."""

    def test_entropy_sufficient(self):
        """
        Password panjang 16 dari pool ~90 karakter memiliki entropi ~103 bit.
        Verifikasi secara tidak langsung: karakter bervariasi.
        """
        pwd = generate_password(64)
        unique_chars = len(set(pwd))
        self.assertGreater(unique_chars, 10,
                           f"Variasi karakter terlalu rendah: hanya {unique_chars} unik dari 64 karakter")

    def test_guaranteed_character_from_each_active_category(self):
        """
        Memverifikasi requirement: minimal 1 karakter dari setiap kategori.
        Dilakukan pada panjang sama dengan jumlah kategori.
        """
        pwd = generate_password(
            4,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True
        )
        self.assertEqual(len(pwd), 4)
        has_upper  = any(c in _UPPERCASE for c in pwd)
        has_lower  = any(c in _LOWERCASE for c in pwd)
        has_digit  = any(c in _DIGITS    for c in pwd)
        has_symbol = any(c in _SYMBOLS   for c in pwd)
        self.assertTrue(has_upper  and has_lower and has_digit and has_symbol,
                        f"Kategori tidak terpenuhi pada panjang minimum: {pwd}")


if __name__ == "__main__":
    print("=" * 60)
    print("Menjalankan unit test CSPRNG...")
    print("=" * 60)
    unittest.main(verbosity=2)
