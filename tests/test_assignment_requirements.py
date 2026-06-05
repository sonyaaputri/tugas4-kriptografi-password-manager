import base64
import json
import os
import shutil
import secrets
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
CLIENT_DIR = os.path.join(ROOT_DIR, "client")
SERVER_DIR = os.path.join(ROOT_DIR, "server")

sys.path.insert(0, CLIENT_DIR)
sys.path.insert(0, os.path.join(CLIENT_DIR, "crypto"))
sys.path.insert(0, SERVER_DIR)

import local_storage as storage
import vault as vault_logic
from cli import available_vault_actions
from crypto.aes_gcm import decrypt_local_share
from crypto.csprng import generate_password
from crypto.kdf import derive_key
from crypto.sss import share_to_string, string_to_share


_TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "_assignment_local_data.json")
_TEST_USERS_DIR = os.path.join(os.path.dirname(__file__), "_assignment_local_users")
storage.LOCAL_DATA_PATH = _TEST_DATA_PATH
storage.LOCAL_USERS_DIR = _TEST_USERS_DIR


def _clear_local_data():
    storage.LOCAL_DATA_PATH = _TEST_DATA_PATH
    storage.LOCAL_USERS_DIR = _TEST_USERS_DIR
    if os.path.exists(_TEST_DATA_PATH):
        os.remove(_TEST_DATA_PATH)
    if os.path.isdir(_TEST_USERS_DIR):
        shutil.rmtree(_TEST_USERS_DIR)


def _make_mock_server():
    server_db = {}

    def register_user(username, server_share, vault_blob, vault_nonce):
        if username in server_db:
            return False, "Username sudah ada"
        server_db[username] = {
            "server_share": server_share,
            "vault_blob": vault_blob,
            "vault_nonce": vault_nonce,
        }
        return True, "OK"

    def fetch_server_data(username):
        if username not in server_db:
            return False, {}
        return True, dict(server_db[username])

    def push_vault(username, vault_blob, vault_nonce):
        if username not in server_db:
            return False, "User tidak ditemukan"
        server_db[username]["vault_blob"] = vault_blob
        server_db[username]["vault_nonce"] = vault_nonce
        return True, "OK"

    return server_db, register_user, fetch_server_data, push_vault


class VaultRequirementTestCase(unittest.TestCase):
    def setUp(self):
        _clear_local_data()
        self.server_db, register, fetch, push = _make_mock_server()
        self.patchers = [
            patch("vault.api.register_user", side_effect=register),
            patch("vault.api.fetch_server_data", side_effect=fetch),
            patch("vault.api.push_vault", side_effect=push),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()
        _clear_local_data()

    def decrypt_local_share(self, username, master_password):
        enc_local_share, nonce, salt, params = storage.load_local_share(username)
        kdf_key, _, _ = derive_key(master_password, salt, params)
        plaintext = decrypt_local_share(enc_local_share, nonce, kdf_key)
        return json.loads(plaintext.decode("utf-8"))


class TestRequirement01CreateVault(VaultRequirementTestCase):
    def test_create_vault_splits_master_key_and_stores_initial_data(self):
        recovery = vault_logic.create_vault("req_create", "MasterPass123!")

        self.assertIsNotNone(recovery)
        self.assertEqual(recovery["index"], 3)
        recovery_text = share_to_string(recovery)
        parsed_recovery = string_to_share(recovery_text)
        self.assertEqual(parsed_recovery, recovery)

        local_share = self.decrypt_local_share("req_create", "MasterPass123!")
        server_share = self.server_db["req_create"]["server_share"]

        self.assertEqual(local_share["index"], 1)
        self.assertEqual(server_share["index"], 2)
        self.assertEqual(recovery["index"], 3)
        self.assertIsInstance(self.server_db["req_create"]["vault_blob"], bytes)
        self.assertNotEqual(self.server_db["req_create"]["vault_blob"], b"[]")
        self.assertIn("vault_nonce", self.server_db["req_create"])


class TestRequirement02LocalShareProtection(VaultRequirementTestCase):
    def test_local_share_is_encrypted_and_password_protected(self):
        recovery = vault_logic.create_vault("req_local", "MasterPass123!")
        local_share = self.decrypt_local_share("req_local", "MasterPass123!")

        with open(storage.get_local_data_path("req_local"), "r") as file:
            local_file_text = file.read()

        self.assertNotIn(local_share["value"], local_file_text)
        self.assertNotIn(recovery["value"], local_file_text)
        self.assertEqual(local_share["index"], 1)

        enc_local_share, nonce, salt, params = storage.load_local_share("req_local")
        wrong_key, _, _ = derive_key("WrongPass123!", salt, params)
        with self.assertRaises(Exception):
            decrypt_local_share(enc_local_share, nonce, wrong_key)


class TestRequirement03NormalAccess(VaultRequirementTestCase):
    def test_normal_access_uses_local_and_server_share(self):
        vault_logic.create_vault("req_normal", "MasterPass123!")

        vault = vault_logic.open_vault_normal("req_normal", "MasterPass123!")
        wrong = vault_logic.open_vault_normal("req_normal", "WrongPass123!")

        self.assertEqual(vault, [])
        self.assertIsNone(wrong)


class TestRequirement04AddPassword(VaultRequirementTestCase):
    def test_add_manual_and_generated_password_updates_server_and_backup(self):
        vault_logic.create_vault("req_add", "MasterPass123!")
        vault = vault_logic.open_vault_normal("req_add", "MasterPass123!")
        old_nonce = self.server_db["req_add"]["vault_nonce"]
        old_backup = storage.load_backup_vault("req_add")

        vault = vault_logic.add_entry(
            "req_add",
            vault,
            "MasterPass123!",
            "GitHub",
            "user@example.com",
            "manual-password",
            "manual",
        )
        generated = generate_password(18)
        vault = vault_logic.add_entry(
            "req_add",
            vault,
            "MasterPass123!",
            "GitLab",
            "dev@example.com",
            generated,
            "generated",
        )

        new_backup = storage.load_backup_vault("req_add")
        self.assertEqual(len(vault), 2)
        self.assertEqual(len(generated), 18)
        self.assertNotEqual(old_nonce, self.server_db["req_add"]["vault_nonce"])
        self.assertNotEqual(old_backup, new_backup)


class TestRequirement05EditDeleteAndBackupReadOnly(VaultRequirementTestCase):
    def test_edit_delete_and_cli_disables_mutation_in_backup_mode(self):
        vault_logic.create_vault("req_edit_delete", "MasterPass123!")
        vault = vault_logic.open_vault_normal("req_edit_delete", "MasterPass123!")
        vault = vault_logic.add_entry("req_edit_delete", vault, "MasterPass123!", "A", "a@a.com", "old", "")
        vault = vault_logic.edit_entry("req_edit_delete", vault, "MasterPass123!", 0, password="new")
        self.assertEqual(vault[0]["password"], "new")

        vault = vault_logic.delete_entry("req_edit_delete", vault, "MasterPass123!", 0)
        reopened = vault_logic.open_vault_normal("req_edit_delete", "MasterPass123!")
        self.assertEqual(vault, [])
        self.assertEqual(reopened, [])

        self.assertIn("add", available_vault_actions("normal"))
        self.assertNotIn("add", available_vault_actions("backup"))
        self.assertNotIn("edit", available_vault_actions("backup"))
        self.assertNotIn("delete", available_vault_actions("backup"))


class TestRequirement06ServerStorage(unittest.TestCase):
    def test_sqlite_server_stores_only_ciphertext_share_nonce_and_metadata(self):
        import database as server_database

        with tempfile.TemporaryDirectory() as tmp_dir:
            old_path = server_database.DB_PATH
            db_path = os.path.join(tmp_dir, "server_test.db")
            server_database.DB_PATH = db_path
            try:
                server_database.init_db()
                vault_blob = b"\x01\x02encrypted-vault"
                server_share = '{"index": 2, "value": "abcd"}'
                server_database.create_user(
                    "sqlite_user",
                    server_share,
                    vault_blob,
                    "00" * 12,
                )

                user = server_database.get_user("sqlite_user")
                conn = sqlite3.connect(db_path)
                try:
                    columns = {
                        row[1]
                        for row in conn.execute("PRAGMA table_info(users)")
                    }
                    blob_type = conn.execute(
                        "SELECT typeof(vault_blob) FROM users WHERE username = ?",
                        ("sqlite_user",),
                    ).fetchone()[0]
                finally:
                    conn.close()

                self.assertEqual(user["server_share"], server_share)
                self.assertEqual(user["vault_blob"], vault_blob)
                self.assertEqual(blob_type, "blob")
                self.assertNotIn("nama_layanan", columns)
                self.assertNotIn("password", columns)
                self.assertNotIn("local_share", columns)
                self.assertNotIn("recovery_share", columns)
                self.assertNotIn("master_key", columns)
            finally:
                server_database.DB_PATH = old_path


class TestRequirement07BackupMode(VaultRequirementTestCase):
    def test_backup_mode_reads_local_backup_without_server(self):
        recovery = vault_logic.create_vault("req_backup", "MasterPass123!")
        vault = vault_logic.open_vault_normal("req_backup", "MasterPass123!")
        vault_logic.add_entry("req_backup", vault, "MasterPass123!", "Mail", "m@example.com", "pw", "")

        with patch("vault.api.fetch_server_data", return_value=(False, {})):
            backup_vault = vault_logic.open_vault_backup("req_backup", "MasterPass123!", recovery)

        self.assertIsNotNone(backup_vault)
        self.assertEqual(backup_vault[0]["nama_layanan"], "Mail")


class TestRequirement08RecoveryFailures(VaultRequirementTestCase):
    def test_wrong_recovery_share_and_tampered_backup_fail_closed(self):
        recovery = vault_logic.create_vault("req_fail", "MasterPass123!")
        wrong_share = {
            "index": recovery["index"],
            "value": secrets.token_hex(len(recovery["value"]) // 2),
        }

        self.assertIsNone(vault_logic.open_vault_backup("req_fail", "MasterPass123!", wrong_share))

        local_path = storage.get_local_data_path("req_fail")
        with open(local_path, "r") as file:
            local_data = json.load(file)
        blob = bytearray(base64.b64decode(local_data["enc_backup_vault"]))
        blob[0] ^= 0x01
        local_data["enc_backup_vault"] = base64.b64encode(bytes(blob)).decode()
        with open(local_path, "w") as file:
            json.dump(local_data, file)

        self.assertIsNone(vault_logic.open_vault_backup("req_fail", "MasterPass123!", recovery))


class TestRequirement09VisualCryptographyBonus(unittest.TestCase):
    def test_visual_secret_sharing_creates_qr_shares_and_reconstruction(self):
        try:
            from PIL import Image
            from crypto.visual_secret import create_visual_shares, reconstruct_and_verify
        except ImportError as exc:
            self.skipTest(f"Visual secret dependency unavailable: {exc}")

        recovery_text = "SSS:3:" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp_dir:
            qr_path, share1_path, share2_path = create_visual_shares(
                recovery_text,
                output_dir=tmp_dir,
            )
            reconstructed_path = reconstruct_and_verify(
                share1_path,
                share2_path,
                os.path.join(tmp_dir, "reconstructed_qr.png"),
            )

            for path in [qr_path, share1_path, share2_path, reconstructed_path]:
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 0)

            original_qr = Image.open(qr_path).convert("L")
            reconstructed = Image.open(reconstructed_path).convert("L")
            self.assertEqual(reconstructed.size, original_qr.size)
            self.assertLessEqual(set(reconstructed.tobytes()), {0, 255})
            self.assertGreater(len(set(reconstructed.tobytes())), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
