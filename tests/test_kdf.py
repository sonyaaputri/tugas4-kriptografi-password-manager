# Unit Test untuk client/crypto/kdf.py
#
# Menguji:
#   1. derive_key menghasilkan 32 bytes key
#   2. Password yang sama + salt yang sama → key yang sama (deterministic)
#   3. Password yang sama + salt berbeda → key yang berbeda
#   4. Password berbeda + salt sama → key yang berbeda
#   5. Mode create (salt=None) menghasilkan salt baru setiap kali
#   6. Mode login (salt diberikan) menghasilkan key yang sama
#   7. Parameter KDF disimpan dengan benar
#   8. Integrasi: key dari KDF bisa digunakan untuk AES-256-GCM

import sys
import os
import unittest
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client", "crypto"))

from crypto.kdf import derive_key, get_default_params


class TestDeriveKey(unittest.TestCase):
    """Uji fungsi derive_key."""

    def test_returns_three_values(self):
        """derive_key mengembalikan tuple (key, salt, params)."""
        result = derive_key("test_password")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)

    def test_key_is_32_bytes(self):
        """Kunci yang dihasilkan harus 32 bytes (256-bit untuk AES-256)."""
        key, _, _ = derive_key("master_password_test")
        self.assertEqual(len(key), 32)

    def test_salt_is_16_bytes(self):
        """Salt yang dibangkitkan harus 16 bytes."""
        _, salt, _ = derive_key("master_password_test")
        self.assertEqual(len(salt), 16)

    def test_params_has_required_fields(self):
        """Parameter KDF harus memuat field yang diperlukan."""
        _, _, params = derive_key("test")
        required_fields = ["time_cost", "memory_cost", "parallelism", "hash_len", "type"]
        for field in required_fields:
            self.assertIn(field, params, f"Field '{field}' tidak ditemukan di params")

    def test_params_type_is_argon2id(self):
        """Tipe KDF harus Argon2id."""
        _, _, params = derive_key("test")
        self.assertEqual(params["type"], "argon2id")

    def test_same_password_same_salt_same_key(self):
        """Password + salt yang sama harus menghasilkan key yang sama (deterministic)."""
        password = "my_master_password_123!"
        # Derive pertama: dapatkan salt
        key1, salt, params = derive_key(password)
        # Derive kedua dengan salt yang sama
        key2, _, _ = derive_key(password, salt, params)
        self.assertEqual(key1, key2,
            "Argon2id harus deterministik dengan password dan salt yang sama")

    def test_same_password_different_salt_different_key(self):
        """Password sama tapi salt berbeda harus menghasilkan key berbeda."""
        password = "same_password"
        key1, salt1, params = derive_key(password)
        # Generate salt baru secara manual
        salt2 = secrets.token_bytes(16)
        self.assertNotEqual(salt1, salt2)

        key2, _, _ = derive_key(password, salt2, params)
        self.assertNotEqual(key1, key2,
            "Salt berbeda HARUS menghasilkan key berbeda")

    def test_different_password_same_salt_different_key(self):
        """Password berbeda dengan salt yang sama harus menghasilkan key berbeda."""
        salt = secrets.token_bytes(16)
        params = get_default_params()

        key1, _, _ = derive_key("password_one", salt, params)
        key2, _, _ = derive_key("password_two", salt, params)

        self.assertNotEqual(key1, key2,
            "Password berbeda HARUS menghasilkan key berbeda")

    def test_new_salt_each_call_without_salt(self):
        """Setiap panggilan tanpa salt menghasilkan salt baru."""
        _, salt1, _ = derive_key("test_password")
        _, salt2, _ = derive_key("test_password")
        self.assertNotEqual(salt1, salt2,
            "Salt harus selalu baru jika tidak diberikan")

    def test_unicode_password(self):
        """Password dengan karakter Unicode harus berjalan normal."""
        unicode_password = "p@$$w0rd_测试_αβγ_emoji🔐"
        key, salt, params = derive_key(unicode_password)
        self.assertEqual(len(key), 32)

        # Rekonstruksi dengan password unicode yang sama
        key2, _, _ = derive_key(unicode_password, salt, params)
        self.assertEqual(key, key2)

    def test_empty_password(self):
        """Password kosong harus tetap berjalan (tidak crash)."""
        key, _, _ = derive_key("")
        self.assertEqual(len(key), 32)

    def test_long_password(self):
        """Password panjang (256 chars) harus berjalan normal."""
        long_password = "A" * 256
        key, salt, params = derive_key(long_password)
        self.assertEqual(len(key), 32)

        key2, _, _ = derive_key(long_password, salt, params)
        self.assertEqual(key, key2)


class TestKDFIntegration(unittest.TestCase):
    """Uji integrasi KDF dalam skenario nyata."""

    def test_kdf_key_usable_for_aes256_gcm(self):
        """
        Key dari KDF harus bisa digunakan langsung untuk AES-256-GCM.
        Uji dengan enkripsi/dekripsi local share.
        """
        from crypto.aes_gcm import encrypt_local_share, decrypt_local_share

        password = "master_password_vault"
        local_share_bytes = b'{"index": 1, "value": "a1b2c3d4e5f6" * 8}'

        # Derive key (mode create)
        kdf_key, salt, params = derive_key(password)

        # Enkripsi local share
        ciphertext, nonce = encrypt_local_share(local_share_bytes, kdf_key)

        # Derive key ulang (mode login, dengan salt tersimpan)
        kdf_key_login, _, _ = derive_key(password, salt, params)
        self.assertEqual(kdf_key, kdf_key_login)

        # Dekripsi berhasil
        decrypted = decrypt_local_share(ciphertext, nonce, kdf_key_login)
        self.assertEqual(decrypted, local_share_bytes)

    def test_wrong_password_cannot_decrypt_local_share(self):
        """
        Password salah menghasilkan key yang berbeda → dekripsi local share gagal.
        Ini adalah property keamanan utama sistem.
        """
        from crypto.aes_gcm import encrypt_local_share, decrypt_local_share
        from cryptography.exceptions import InvalidTag

        correct_password = "correct_master_password"
        wrong_password   = "wrong_master_password"
        local_share_bytes = b'{"index": 1, "value": "deadbeef" * 8}'

        # Derive key dengan password benar
        kdf_key_correct, salt, params = derive_key(correct_password)
        ciphertext, nonce = encrypt_local_share(local_share_bytes, kdf_key_correct)

        # Coba dekripsi dengan password salah (menggunakan salt yang sama)
        kdf_key_wrong, _, _ = derive_key(wrong_password, salt, params)
        self.assertNotEqual(kdf_key_correct, kdf_key_wrong)

        with self.assertRaises(InvalidTag,
            msg="Password salah HARUS menyebabkan dekripsi gagal"):
            decrypt_local_share(ciphertext, nonce, kdf_key_wrong)

    def test_params_serializable_to_json(self):
        """
        Parameter KDF harus bisa disimpan dan dibaca dari JSON
        (karena disimpan di local_data.json).
        """
        import json

        _, _, params = derive_key("test_password")

        # Harus bisa di-serialize ke JSON
        json_str = json.dumps(params)
        self.assertIsInstance(json_str, str)

        # Harus bisa di-parse kembali
        parsed = json.loads(json_str)
        self.assertEqual(parsed, params)

    def test_default_params_memory_cost(self):
        """Parameter default harus memenuhi rekomendasi keamanan OWASP."""
        params = get_default_params()
        # OWASP merekomendasikan memory_cost >= 64 MB = 65536 KiB
        self.assertGreaterEqual(params["memory_cost"], 65536,
            "memory_cost harus >= 64 MB untuk keamanan yang memadai")
        # time_cost >= 1
        self.assertGreaterEqual(params["time_cost"], 1)
        # hash_len >= 16 bytes
        self.assertGreaterEqual(params["hash_len"], 16)


if __name__ == "__main__":
    print("=" * 60)
    print("Menjalankan unit test KDF (Argon2id)...")
    print("=" * 60)
    unittest.main(verbosity=2)