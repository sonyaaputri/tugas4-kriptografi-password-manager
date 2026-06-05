# Unit Test untuk client/vault.py
#
# Menguji alur end-to-end:
#   1. Pembuatan vault (create_vault)
#   2. Akses normal (open_vault_normal)
#   3. Akses backup (open_vault_backup)
#   4. Operasi CRUD (add_entry, edit_entry, delete_entry)
#   5. Kegagalan autentikasi (password salah, share salah)
#
# Test menggunakan mock untuk mengisolasi dari server HTTP.

import sys
import os
import json
import shutil
import secrets
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client", "crypto"))

import vault as vault_logic
import local_storage as storage

# Agar test tidak menghapus data user asli di client/local_users
_TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "_test_local_data.json")
_TEST_USERS_DIR = os.path.join(os.path.dirname(__file__), "_test_local_users")
storage.LOCAL_DATA_PATH = _TEST_DATA_PATH
storage.LOCAL_USERS_DIR = _TEST_USERS_DIR


# Helper: bersihkan data lokal setelah setiap test 
def _clear():
    """Hapus file test sementara agar tiap test mulai bersih."""
    storage.LOCAL_DATA_PATH = _TEST_DATA_PATH  # pastikan selalu mengarah ke file test
    storage.LOCAL_USERS_DIR = _TEST_USERS_DIR
    if os.path.exists(_TEST_DATA_PATH):
        os.remove(_TEST_DATA_PATH)
    if os.path.isdir(_TEST_USERS_DIR):
        shutil.rmtree(_TEST_USERS_DIR)

def _make_mock_server():
    """
    Membuat mock untuk api_client yang mensimulasikan server aktif.
    Menyimpan data vault di memori agar bisa dicek antar pemanggilan.
    """
    server_db = {}  # username → {server_share, vault_blob, vault_nonce}

    def mock_register_user(username, server_share, vault_blob, vault_nonce):
        if username in server_db:
            return False, "Username sudah ada"
        server_db[username] = {
            "server_share": server_share,
            "vault_blob"  : vault_blob,
            "vault_nonce" : vault_nonce,
        }
        return True, "OK"

    def mock_fetch_server_data(username):
        if username not in server_db:
            return False, {}
        entry = server_db[username]
        return True, {
            "server_share": entry["server_share"],
            "vault_blob"  : entry["vault_blob"],
            "vault_nonce" : entry["vault_nonce"],
        }

    def mock_push_vault(username, vault_blob, vault_nonce):
        if username not in server_db:
            return False, "User tidak ditemukan"
        server_db[username]["vault_blob"]  = vault_blob
        server_db[username]["vault_nonce"] = vault_nonce
        return True, "OK"

    def mock_is_server_online():
        return True

    return (server_db, mock_register_user, mock_fetch_server_data,
            mock_push_vault, mock_is_server_online)


class TestCreateVault(unittest.TestCase):
    """Uji pembuatan vault baru."""

    def setUp(self):
        _clear()
        (self.server_db, reg, fetch, push, online) = _make_mock_server()
        self.patcher_reg   = patch("vault.api.register_user",   side_effect=reg)
        self.patcher_fetch = patch("vault.api.fetch_server_data", side_effect=fetch)
        self.patcher_push  = patch("vault.api.push_vault",       side_effect=push)
        self.patcher_reg.start()
        self.patcher_fetch.start()
        self.patcher_push.start()

    def tearDown(self):
        self.patcher_reg.stop()
        self.patcher_fetch.stop()
        self.patcher_push.stop()
        _clear()

    def test_create_vault_returns_recovery_share(self):
        """create_vault mengembalikan recovery share (dict dengan index dan value)."""
        recovery = vault_logic.create_vault("userA", "password123!")
        self.assertIsNotNone(recovery, "create_vault seharusnya mengembalikan recovery share")
        self.assertIn("index", recovery)
        self.assertIn("value", recovery)

    def test_recovery_share_index_is_3(self):
        """Recovery share harus memiliki index 3 (share ke-3 dari SSS (2,3))."""
        recovery = vault_logic.create_vault("userB", "password123!")
        self.assertEqual(recovery["index"], 3)

    def test_recovery_share_value_is_hex_string(self):
        """Nilai recovery share harus berupa hex string."""
        recovery = vault_logic.create_vault("userC", "password123!")
        value = recovery["value"]
        self.assertIsInstance(value, str)
        # Pastikan string hex valid
        try:
            int(value, 16)
        except ValueError:
            self.fail(f"recovery share value bukan hex string: {value}")

    def test_server_receives_encrypted_vault(self):
        """Server harus menyimpan vault terenkripsi (bukan plaintext)."""
        vault_logic.create_vault("userD", "password123!")
        self.assertIn("userD", self.server_db)
        vault_blob = self.server_db["userD"]["vault_blob"]
        # Vault blob adalah bytes, bukan JSON langsung
        self.assertIsInstance(vault_blob, bytes)
        # Blob tidak boleh sama dengan vault kosong dalam plaintext
        self.assertNotEqual(vault_blob, b"[]")

    def test_server_stores_server_share(self):
        """Server harus menyimpan server_share."""
        vault_logic.create_vault("userE", "password123!")
        self.assertIn("server_share", self.server_db["userE"])
        server_share = self.server_db["userE"]["server_share"]
        self.assertIsNotNone(server_share)

    def test_local_data_saved_after_create(self):
        """Data lokal harus tersimpan setelah pembuatan vault."""
        vault_logic.create_vault("userF", "password123!")
        self.assertTrue(storage.local_data_exists("userF"),
                        "local_data.json harus ada setelah create_vault")

    def test_local_share_encrypted_not_plaintext(self):
        """Local share harus disimpan dalam bentuk terenkripsi."""
        vault_logic.create_vault("userG", "password123!")
        local_data = storage.load_local_share("userG")
        self.assertIsNotNone(local_data)
        enc_local_share, nonce, kdf_salt, kdf_params = local_data
        # enc_local_share harus bytes (terenkripsi), bukan JSON share langsung
        self.assertIsInstance(enc_local_share, bytes)
        # Tidak boleh berupa JSON yang valid secara langsung
        try:
            parsed = json.loads(enc_local_share.decode("utf-8"))
            # Jika berhasil di-parse, pastikan bukan share plaintext
            self.assertNotIn("index", parsed,
                             "local share seharusnya tidak bisa di-parse sebagai share plaintext")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Diharapkan: enkripsi menghasilkan bytes acak yang bukan JSON

    def test_duplicate_username_returns_none(self):
        """Registrasi dengan username yang sama harus mengembalikan None."""
        vault_logic.create_vault("userH", "password123!")
        _clear()
        result = vault_logic.create_vault("userH", "password456!")
        self.assertIsNone(result, "Username duplikat seharusnya mengembalikan None")

    def test_different_users_get_different_recovery_shares(self):
        """Dua pengguna berbeda mendapat recovery share berbeda."""
        r1 = vault_logic.create_vault("userI", "pass1234!")
        _clear()
        r2 = vault_logic.create_vault("userJ", "pass1234!")
        self.assertNotEqual(r1["value"], r2["value"],
                            "Recovery share dua pengguna berbeda tidak boleh sama")


class TestOpenVaultNormal(unittest.TestCase):
    """Uji akses vault mode normal."""

    def setUp(self):
        _clear()
        (self.server_db, reg, self.fetch, self.push, online) = _make_mock_server()
        self.patcher_reg   = patch("vault.api.register_user",    side_effect=reg)
        self.patcher_fetch = patch("vault.api.fetch_server_data", side_effect=self.fetch)
        self.patcher_push  = patch("vault.api.push_vault",        side_effect=self.push)
        self.patcher_reg.start()
        self.patcher_fetch.start()
        self.patcher_push.start()
        # Buat vault dulu
        self.master_password = "TestPass123!"
        self.username        = "normaluser"
        vault_logic.create_vault(self.username, self.master_password)

    def tearDown(self):
        self.patcher_reg.stop()
        self.patcher_fetch.stop()
        self.patcher_push.stop()
        _clear()

    def test_open_vault_normal_returns_list(self):
        """open_vault_normal mengembalikan list (vault)."""
        vault = vault_logic.open_vault_normal(self.username, self.master_password)
        self.assertIsNotNone(vault)
        self.assertIsInstance(vault, list)

    def test_open_vault_empty_initially(self):
        """Vault baru harus kosong (list kosong)."""
        vault = vault_logic.open_vault_normal(self.username, self.master_password)
        self.assertEqual(vault, [])

    def test_wrong_password_returns_none(self):
        """Password salah harus mengembalikan None (akses ditolak)."""
        result = vault_logic.open_vault_normal(self.username, "SalahPassword!")
        self.assertIsNone(result,
                          "Password salah seharusnya mengembalikan None")

    def test_master_key_reconstructed_from_two_shares(self):
        """
        Verifikasi tidak langsung: vault berhasil dibuka berarti
        local share + server share berhasil merekonstruksi master key.
        """
        vault = vault_logic.open_vault_normal(self.username, self.master_password)
        # Jika vault tidak None, rekonstruksi berhasil
        self.assertIsNotNone(vault)


class TestOpenVaultBackup(unittest.TestCase):
    """Uji akses vault mode backup (tanpa server)."""

    def setUp(self):
        _clear()
        (self.server_db, reg, fetch, push, online) = _make_mock_server()
        self.patcher_reg   = patch("vault.api.register_user",    side_effect=reg)
        self.patcher_fetch = patch("vault.api.fetch_server_data", side_effect=fetch)
        self.patcher_push  = patch("vault.api.push_vault",        side_effect=push)
        self.patcher_reg.start()
        self.patcher_fetch.start()
        self.patcher_push.start()

        self.master_password = "BackupPass456!"
        self.username        = "backupuser"
        self.recovery_share  = vault_logic.create_vault(self.username, self.master_password)

    def tearDown(self):
        self.patcher_reg.stop()
        self.patcher_fetch.stop()
        self.patcher_push.stop()
        _clear()

    def test_open_backup_with_correct_recovery_share(self):
        """Membuka vault backup dengan recovery share yang benar harus berhasil."""
        vault = vault_logic.open_vault_backup(self.username, self.master_password, self.recovery_share)
        self.assertIsNotNone(vault, "Backup vault seharusnya berhasil dibuka")
        self.assertIsInstance(vault, list)

    def test_open_backup_wrong_password_returns_none(self):
        """Password salah pada mode backup harus mengembalikan None."""
        result = vault_logic.open_vault_backup(self.username, "SalahPass!", self.recovery_share)
        self.assertIsNone(result)

    def test_open_backup_wrong_recovery_share_returns_none(self):
        """Recovery share salah harus mengembalikan None."""
        wrong_share = {
            "index": 3,
            "value": secrets.token_hex(len(self.recovery_share["value"]) // 2)
        }
        result = vault_logic.open_vault_backup(self.username, self.master_password, wrong_share)
        self.assertIsNone(result)

    def test_open_backup_wrong_index_returns_none(self):
        """Recovery share dengan index salah harus mengembalikan None."""
        wrong_share = {"index": 999, "value": self.recovery_share["value"]}
        result = vault_logic.open_vault_backup(self.username, self.master_password, wrong_share)
        self.assertIsNone(result)

    def test_backup_vault_empty_initially(self):
        """Backup vault kosong saat pertama kali dibuat."""
        vault = vault_logic.open_vault_backup(self.username, self.master_password, self.recovery_share)
        self.assertEqual(vault, [])


class TestVaultCRUD(unittest.TestCase):
    """Uji operasi tambah, ubah, hapus password."""

    def setUp(self):
        _clear()
        (self.server_db, reg, fetch, push, online) = _make_mock_server()
        self.patcher_reg   = patch("vault.api.register_user",    side_effect=reg)
        self.patcher_fetch = patch("vault.api.fetch_server_data", side_effect=fetch)
        self.patcher_push  = patch("vault.api.push_vault",        side_effect=push)
        self.patcher_reg.start()
        self.patcher_fetch.start()
        self.patcher_push.start()

        self.master_password = "CRUDPass789!"
        self.username        = "cruduser"
        vault_logic.create_vault(self.username, self.master_password)
        self.vault = vault_logic.open_vault_normal(self.username, self.master_password)

    def tearDown(self):
        self.patcher_reg.stop()
        self.patcher_fetch.stop()
        self.patcher_push.stop()
        _clear()

    # ── Add ──────────────────────────────────────────────────

    def test_add_entry_returns_updated_vault(self):
        """add_entry mengembalikan vault yang diperbarui."""
        new_vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "GitHub", "user@test.com", "p@ssw0rd", "akun utama"
        )
        self.assertIsNotNone(new_vault)
        self.assertEqual(len(new_vault), 1)

    def test_add_entry_content_correct(self):
        """Entry yang ditambahkan memiliki data yang benar."""
        new_vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "GitLab", "dev@test.com", "s3cur3!", "akun dev"
        )
        entry = new_vault[0]
        self.assertEqual(entry["nama_layanan"], "GitLab")
        self.assertEqual(entry["username"],     "dev@test.com")
        self.assertEqual(entry["password"],     "s3cur3!")
        self.assertEqual(entry["catatan"],      "akun dev")

    def test_add_multiple_entries(self):
        """Menambahkan beberapa entry ke vault."""
        vault = self.vault
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "A", "a@a.com", "pa", "")
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "B", "b@b.com", "pb", "")
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "C", "c@c.com", "pc", "")
        self.assertEqual(len(vault), 3)

    def test_add_entry_vault_persisted_to_server(self):
        """Setelah add_entry, vault baru tersimpan di server (nonce berubah)."""
        old_nonce = self.server_db.get(self.username, {}).get("vault_nonce")
        vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "Gmail", "mail@gmail.com", "gmailpass", ""
        )
        new_nonce = self.server_db.get(self.username, {}).get("vault_nonce")
        self.assertNotEqual(old_nonce, new_nonce,
                            "Nonce harus berubah setelah vault dienkripsi ulang")

    def test_add_entry_and_reopen_vault(self):
        """Entry yang ditambahkan tetap ada setelah vault dibuka ulang."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "Twitter", "user@tw.com", "twpass!", ""
        )
        # Buka vault kembali
        reopened = vault_logic.open_vault_normal(self.username, self.master_password)
        self.assertIsNotNone(reopened)
        self.assertEqual(len(reopened), 1)
        self.assertEqual(reopened[0]["nama_layanan"], "Twitter")

    # ── Edit ─────────────────────────────────────────────────

    def test_edit_entry_updates_field(self):
        """edit_entry mengubah field yang ditentukan."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "Netflix", "user@ntf.com", "oldpass", ""
        )
        edited = vault_logic.edit_entry(
            self.username,
            vault, self.master_password, 0,
            password="newpass123"
        )
        self.assertIsNotNone(edited)
        self.assertEqual(edited[0]["password"], "newpass123")
        # Field lain tidak berubah
        self.assertEqual(edited[0]["nama_layanan"], "Netflix")
        self.assertEqual(edited[0]["username"],     "user@ntf.com")

    def test_edit_entry_all_fields(self):
        """edit_entry bisa mengubah semua field sekaligus."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "OldService", "old@u.com", "oldpw", "old note"
        )
        edited = vault_logic.edit_entry(
            self.username,
            vault, self.master_password, 0,
            nama_layanan="NewService",
            username="new@u.com",
            password="newpw123",
            catatan="new note"
        )
        e = edited[0]
        self.assertEqual(e["nama_layanan"], "NewService")
        self.assertEqual(e["username"],     "new@u.com")
        self.assertEqual(e["password"],     "newpw123")
        self.assertEqual(e["catatan"],      "new note")

    def test_edit_invalid_index_returns_none(self):
        """edit_entry dengan index di luar range harus mengembalikan None."""
        result = vault_logic.edit_entry(
            self.username,
            self.vault, self.master_password, 99,
            password="newpass"
        )
        self.assertIsNone(result)

    def test_edit_and_reopen_vault(self):
        """Perubahan dari edit_entry tetap ada setelah vault dibuka ulang."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "Spotify", "sp@test.com", "oldsppass", ""
        )
        vault_logic.edit_entry(
            self.username,
            vault, self.master_password, 0, password="newsppass"
        )
        reopened = vault_logic.open_vault_normal(self.username, self.master_password)
        self.assertEqual(reopened[0]["password"], "newsppass")

    # ── Delete ───────────────────────────────────────────────

    def test_delete_entry_removes_item(self):
        """delete_entry menghapus entry dari vault."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "ToDelete", "del@t.com", "delpw", ""
        )
        self.assertEqual(len(vault), 1)
        new_vault = vault_logic.delete_entry(self.username, vault, self.master_password, 0)
        self.assertIsNotNone(new_vault)
        self.assertEqual(len(new_vault), 0)

    def test_delete_correct_entry_from_multiple(self):
        """delete_entry menghapus entry yang tepat ketika ada beberapa."""
        vault = self.vault
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "A", "a@a.com", "pa", "")
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "B", "b@b.com", "pb", "")
        vault = vault_logic.add_entry(self.username, vault, self.master_password, "C", "c@c.com", "pc", "")
        # Hapus entry index 1 (B)
        new_vault = vault_logic.delete_entry(self.username, vault, self.master_password, 1)
        self.assertEqual(len(new_vault), 2)
        names = [e["nama_layanan"] for e in new_vault]
        self.assertNotIn("B", names)
        self.assertIn("A", names)
        self.assertIn("C", names)

    def test_delete_invalid_index_returns_none(self):
        """delete_entry dengan index tidak valid mengembalikan None."""
        result = vault_logic.delete_entry(self.username, self.vault, self.master_password, 99)
        self.assertIsNone(result)

    def test_delete_and_reopen_vault(self):
        """Entry yang dihapus tidak muncul setelah vault dibuka ulang."""
        vault = vault_logic.add_entry(
            self.username,
            self.vault, self.master_password,
            "Deleted", "del@test.com", "delpw", ""
        )
        vault_logic.delete_entry(self.username, vault, self.master_password, 0)
        reopened = vault_logic.open_vault_normal(self.username, self.master_password)
        self.assertEqual(reopened, [])


class TestVaultSecurity(unittest.TestCase):
    """Uji sifat keamanan vault."""

    def setUp(self):
        _clear()
        (self.server_db, reg, fetch, push, online) = _make_mock_server()
        self.patcher_reg   = patch("vault.api.register_user",    side_effect=reg)
        self.patcher_fetch = patch("vault.api.fetch_server_data", side_effect=fetch)
        self.patcher_push  = patch("vault.api.push_vault",        side_effect=push)
        self.patcher_reg.start()
        self.patcher_fetch.start()
        self.patcher_push.start()

    def tearDown(self):
        self.patcher_reg.stop()
        self.patcher_fetch.stop()
        self.patcher_push.stop()
        _clear()

    def test_vault_blob_is_encrypted_not_plaintext(self):
        """Vault yang disimpan di server harus terenkripsi (bukan JSON plaintext)."""
        vault_logic.create_vault("secuser", "SecPass!")
        vault_blob = self.server_db["secuser"]["vault_blob"]
        # Tidak boleh bisa di-parse sebagai JSON langsung
        try:
            parsed = json.loads(vault_blob)
            self.fail("vault_blob seharusnya tidak bisa di-parse sebagai JSON — harusnya terenkripsi")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Diharapkan

    def test_server_does_not_store_plaintext_passwords(self):
        """
        Verifikasi: vault_blob di server tidak mengandung plaintext password.
        """
        vault_logic.create_vault("sec2user", "SecPass!")
        vault_blob = self.server_db["sec2user"]["vault_blob"]
        # String 'password_tes' tidak boleh ada di blob
        self.assertNotIn(b"password_tes", vault_blob)
        self.assertNotIn(b"nama_layanan", vault_blob)

    def test_different_passwords_produce_different_local_shares(self):
        """
        Dua user dengan master password berbeda menghasilkan
        local share terenkripsi yang berbeda (karena kunci KDF berbeda).
        """
        vault_logic.create_vault("diffuser1", "PassA111!")
        local_data1 = storage.load_local_share("diffuser1")
        _clear()

        vault_logic.create_vault("diffuser2", "PassB222!")
        local_data2 = storage.load_local_share("diffuser2")

        self.assertNotEqual(local_data1[0], local_data2[0],
                            "Local share terenkripsi seharusnya berbeda untuk password berbeda")

    def test_nonce_changes_after_vault_update(self):
        """Setelah update vault, nonce harus berbeda (AES-GCM requirement)."""
        vault_logic.create_vault("nonceuser", "NoncePass!")
        nonce1 = self.server_db["nonceuser"]["vault_nonce"]

        vault = vault_logic.open_vault_normal("nonceuser", "NoncePass!")
        vault_logic.add_entry("nonceuser", vault, "NoncePass!", "Srv", "u@u.com", "pw", "")
        nonce2 = self.server_db["nonceuser"]["vault_nonce"]

        self.assertNotEqual(nonce1, nonce2,
                            "Nonce harus selalu baru setiap enkripsi ulang vault")

    def test_modified_vault_blob_fails_decryption(self):
        """Vault yang dimodifikasi di server harus gagal didekripsi (AES-GCM auth)."""
        vault_logic.create_vault("tamperuser", "TamperPass!")
        # Modifikasi vault_blob di server
        original_blob = self.server_db["tamperuser"]["vault_blob"]
        tampered = bytearray(original_blob)
        tampered[0] ^= 0xFF
        self.server_db["tamperuser"]["vault_blob"] = bytes(tampered)

        # Dekripsi harus gagal
        result = vault_logic.open_vault_normal("tamperuser", "TamperPass!")
        self.assertIsNone(result,
                          "Vault yang dimodifikasi seharusnya gagal didekripsi")


if __name__ == "__main__":
    print("=" * 60)
    print("Menjalankan unit test Vault...")
    print("=" * 60)
    unittest.main(verbosity=2)
