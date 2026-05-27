# Unit Test untuk client/crypto/aes_gcm.py
#
# Menguji:
#   1. Enkripsi vault menghasilkan ciphertext berbeda dari plaintext
#   2. Dekripsi vault menghasilkan plaintext asli
#   3. Enkripsi dengan key berbeda menghasilkan ciphertext berbeda
#   4. Enkripsi dua kali menghasilkan nonce berbeda
#   5. Dekripsi gagal jika key salah (InvalidTag)
#   6. Dekripsi gagal jika ciphertext dimodifikasi (InvalidTag)
#   7. Dekripsi gagal jika nonce salah (InvalidTag)
#   8. Enkripsi/dekripsi local share (AES-256-GCM)
#   9. Validasi ukuran key

import sys
import os
import unittest
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client", "crypto"))

from crypto.aes_gcm import (
    encrypt_vault,
    decrypt_vault,
    encrypt_local_share,
    decrypt_local_share,
)
from cryptography.exceptions import InvalidTag


class TestEncryptDecryptVault(unittest.TestCase):
    """Uji enkripsi dan dekripsi vault (AES-128-GCM)."""

    def setUp(self):
        """Setup: buat master key 16 bytes dan contoh vault."""
        self.master_key = secrets.token_bytes(16)
        self.vault_data = b'[{"nama_layanan": "GitHub", "username": "user@example.com", "password": "s3cr3t!", "catatan": ""}]'

    def test_encrypt_returns_two_values(self):
        """encrypt_vault mengembalikan tuple (ciphertext, nonce)."""
        result = encrypt_vault(self.vault_data, self.master_key)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_ciphertext_different_from_plaintext(self):
        """Ciphertext berbeda dari plaintext."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        self.assertNotEqual(ciphertext, self.vault_data)

    def test_nonce_is_12_bytes(self):
        """Nonce harus 12 bytes (96-bit, rekomendasi NIST untuk AES-GCM)."""
        _, nonce = encrypt_vault(self.vault_data, self.master_key)
        self.assertEqual(len(nonce), 12)

    def test_encrypt_twice_different_nonce(self):
        """Dua enkripsi berturut-turut menghasilkan nonce berbeda."""
        _, nonce1 = encrypt_vault(self.vault_data, self.master_key)
        _, nonce2 = encrypt_vault(self.vault_data, self.master_key)
        self.assertNotEqual(nonce1, nonce2, "Nonce HARUS selalu baru setiap enkripsi")

    def test_encrypt_twice_different_ciphertext(self):
        """Dua enkripsi dengan plaintext sama menghasilkan ciphertext berbeda."""
        ct1, _ = encrypt_vault(self.vault_data, self.master_key)
        ct2, _ = encrypt_vault(self.vault_data, self.master_key)
        self.assertNotEqual(ct1, ct2)

    def test_decrypt_returns_original_plaintext(self):
        """Dekripsi menghasilkan plaintext yang sama dengan input."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        decrypted = decrypt_vault(ciphertext, nonce, self.master_key)
        self.assertEqual(decrypted, self.vault_data)

    def test_decrypt_empty_vault(self):
        """Enkripsi dan dekripsi vault kosong (list kosong)."""
        empty_vault = b"[]"
        ciphertext, nonce = encrypt_vault(empty_vault, self.master_key)
        decrypted = decrypt_vault(ciphertext, nonce, self.master_key)
        self.assertEqual(decrypted, empty_vault)

    def test_decrypt_wrong_key_raises_invalid_tag(self):
        """Dekripsi dengan key salah harus raise InvalidTag."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        wrong_key = secrets.token_bytes(16)
        with self.assertRaises(InvalidTag):
            decrypt_vault(ciphertext, nonce, wrong_key)

    def test_decrypt_modified_ciphertext_raises_invalid_tag(self):
        """Dekripsi ciphertext yang dimodifikasi harus raise InvalidTag."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        # Modifikasi 1 byte di ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            decrypt_vault(bytes(tampered), nonce, self.master_key)

    def test_decrypt_wrong_nonce_raises_invalid_tag(self):
        """Dekripsi dengan nonce salah harus raise InvalidTag."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        wrong_nonce = secrets.token_bytes(12)
        with self.assertRaises(InvalidTag):
            decrypt_vault(ciphertext, wrong_nonce, self.master_key)

    def test_invalid_key_size_raises_value_error(self):
        """Key selain 16 bytes harus raise ValueError."""
        with self.assertRaises(ValueError):
            encrypt_vault(self.vault_data, secrets.token_bytes(32))  # 32 bytes
        with self.assertRaises(ValueError):
            encrypt_vault(self.vault_data, secrets.token_bytes(8))   # 8 bytes

    def test_decrypt_invalid_key_size_raises_value_error(self):
        """Dekripsi dengan key selain 16 bytes harus raise ValueError."""
        ciphertext, nonce = encrypt_vault(self.vault_data, self.master_key)
        with self.assertRaises(ValueError):
            decrypt_vault(ciphertext, nonce, secrets.token_bytes(32))

    def test_different_key_produces_different_ciphertext(self):
        """Dua key berbeda menghasilkan ciphertext berbeda."""
        key2 = secrets.token_bytes(16)
        ct1, _ = encrypt_vault(self.vault_data, self.master_key)
        ct2, _ = encrypt_vault(self.vault_data, key2)
        self.assertNotEqual(ct1, ct2)


class TestEncryptDecryptLocalShare(unittest.TestCase):
    """Uji enkripsi dan dekripsi local share (AES-256-GCM)."""

    def setUp(self):
        """Setup: buat kdf_key 32 bytes dan contoh local share."""
        self.kdf_key = secrets.token_bytes(32)
        self.local_share_data = b'{"index": 1, "value": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}'

    def test_encrypt_returns_tuple(self):
        """encrypt_local_share mengembalikan tuple (ciphertext, nonce)."""
        result = encrypt_local_share(self.local_share_data, self.kdf_key)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_nonce_is_12_bytes(self):
        """Nonce local share harus 12 bytes."""
        _, nonce = encrypt_local_share(self.local_share_data, self.kdf_key)
        self.assertEqual(len(nonce), 12)

    def test_decrypt_returns_original(self):
        """Dekripsi local share menghasilkan data asli."""
        ciphertext, nonce = encrypt_local_share(self.local_share_data, self.kdf_key)
        decrypted = decrypt_local_share(ciphertext, nonce, self.kdf_key)
        self.assertEqual(decrypted, self.local_share_data)

    def test_wrong_key_raises_invalid_tag(self):
        """Dekripsi local share dengan key salah (master password salah) harus raise InvalidTag."""
        ciphertext, nonce = encrypt_local_share(self.local_share_data, self.kdf_key)
        wrong_kdf_key = secrets.token_bytes(32)
        with self.assertRaises(InvalidTag):
            decrypt_local_share(ciphertext, nonce, wrong_kdf_key)

    def test_modified_ciphertext_raises_invalid_tag(self):
        """Modifikasi local share terenkripsi harus terdeteksi (AES-GCM auth)."""
        ciphertext, nonce = encrypt_local_share(self.local_share_data, self.kdf_key)
        tampered = bytearray(ciphertext)
        tampered[5] ^= 0x01
        with self.assertRaises(InvalidTag):
            decrypt_local_share(bytes(tampered), nonce, self.kdf_key)

    def test_invalid_key_size_raises_value_error(self):
        """KDF key selain 32 bytes harus raise ValueError."""
        with self.assertRaises(ValueError):
            encrypt_local_share(self.local_share_data, secrets.token_bytes(16))  # 16 bytes

    def test_256bit_key_vs_128bit_key(self):
        """AES-256-GCM menggunakan 32-byte key, bukan 16-byte."""
        # Ini memastikan local share menggunakan AES-256 (lebih kuat)
        # sementara vault menggunakan AES-128
        kdf_key_256 = secrets.token_bytes(32)
        ciphertext, nonce = encrypt_local_share(self.local_share_data, kdf_key_256)
        decrypted = decrypt_local_share(ciphertext, nonce, kdf_key_256)
        self.assertEqual(decrypted, self.local_share_data)


class TestAESGCMIntegration(unittest.TestCase):
    """Uji integrasi AES-GCM dalam skenario vault nyata."""

    def test_full_vault_lifecycle(self):
        """
        Simulasi siklus hidup vault:
        1. Enkripsi vault kosong
        2. Dekripsi → tambah entry → enkripsi ulang dengan nonce baru
        3. Dekripsi vault baru → verifikasi entry ada
        """
        import json

        master_key = secrets.token_bytes(16)

        # 1. Enkripsi vault kosong
        empty_vault = json.dumps([]).encode("utf-8")
        ct1, nonce1 = encrypt_vault(empty_vault, master_key)

        # 2. Dekripsi, tambah entry, enkripsi ulang
        vault_data = json.loads(decrypt_vault(ct1, nonce1, master_key))
        vault_data.append({
            "nama_layanan": "GitHub",
            "username"    : "user@test.com",
            "password"    : "p@ssw0rd",
            "catatan"     : ""
        })
        vault_bytes = json.dumps(vault_data).encode("utf-8")
        ct2, nonce2 = encrypt_vault(vault_bytes, master_key)

        # Nonce harus berbeda setelah enkripsi ulang
        self.assertNotEqual(nonce1, nonce2)

        # 3. Dekripsi vault baru
        decrypted = json.loads(decrypt_vault(ct2, nonce2, master_key))
        self.assertEqual(len(decrypted), 1)
        self.assertEqual(decrypted[0]["nama_layanan"], "GitHub")
        self.assertEqual(decrypted[0]["password"], "p@ssw0rd")

    def test_backup_vault_same_key(self):
        """
        Backup vault menggunakan key yang sama dengan vault utama
        (karena key berasal dari rekonstruksi SSS yang sama).
        """
        master_key = secrets.token_bytes(16)
        vault_content = b'[{"nama_layanan": "test", "username": "u", "password": "p", "catatan": ""}]'

        # Enkripsi vault utama
        ct_main, nonce_main = encrypt_vault(vault_content, master_key)

        # Enkripsi backup (nonce berbeda!)
        ct_backup, nonce_backup = encrypt_vault(vault_content, master_key)

        self.assertNotEqual(nonce_main, nonce_backup)

        # Keduanya bisa didekripsi dengan key yang sama
        decrypted_main   = decrypt_vault(ct_main, nonce_main, master_key)
        decrypted_backup = decrypt_vault(ct_backup, nonce_backup, master_key)

        self.assertEqual(decrypted_main, decrypted_backup)
        self.assertEqual(decrypted_main, vault_content)


if __name__ == "__main__":
    print("=" * 60)
    print("Menjalankan unit test AES-GCM...")
    print("=" * 60)
    unittest.main(verbosity=2)