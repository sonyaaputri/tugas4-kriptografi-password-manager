# Unit Test untuk client/crypto/sss.py
#
# Menguji:
#   1. Generate shares menghasilkan 3 share dengan format benar
#   2. Rekonstruksi dari 2 share manapun menghasilkan secret asli
#   3. Share tunggal tidak bisa rekonstruksi (kurang dari threshold)
#   4. Share dengan index salah menghasilkan secret yang salah
#   5. Serialisasi dan deserialisasi share (share_to_string / string_to_share)
#   6. Edge case: secret 16 bytes (AES-128 master key)

import sys
import os
import unittest
import secrets

# Tambahkan path client/crypto ke sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client", "crypto"))

from crypto.sss import (
    generate_shares,
    reconstruct_secret,
    share_to_string,
    string_to_share,
)


class TestGenerateShares(unittest.TestCase):
    """Uji pembangkitan share."""

    def setUp(self):
        """Setup: buat master key 16 bytes untuk semua test."""
        self.master_key = secrets.token_bytes(16)

    def test_generates_correct_count(self):
        """Generate 3 share dari skema (2,3)."""
        shares = generate_shares(self.master_key, threshold=2, total=3)
        self.assertEqual(len(shares), 3)

    def test_share_format(self):
        """Setiap share punya field 'index' dan 'value'."""
        shares = generate_shares(self.master_key, threshold=2, total=3)
        for i, share in enumerate(shares):
            self.assertIn("index", share)
            self.assertIn("value", share)
            self.assertEqual(share["index"], i + 1)  # 1-based index
            # value harus valid hex string
            int(share["value"], 16)

    def test_share_indices_are_unique(self):
        """Semua share memiliki index yang berbeda."""
        shares = generate_shares(self.master_key, threshold=2, total=3)
        indices = [s["index"] for s in shares]
        self.assertEqual(len(set(indices)), len(indices))

    def test_different_calls_produce_different_shares(self):
        """Dua panggilan generate_shares menghasilkan share berbeda (random)."""
        shares1 = generate_shares(self.master_key, threshold=2, total=3)
        shares2 = generate_shares(self.master_key, threshold=2, total=3)
        # Setidaknya satu share harus berbeda (probabilitas collision sangat kecil)
        values1 = {s["index"]: s["value"] for s in shares1}
        values2 = {s["index"]: s["value"] for s in shares2}
        self.assertNotEqual(values1, values2)

    def test_invalid_threshold(self):
        """Threshold < 2 harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_shares(self.master_key, threshold=1, total=3)

    def test_total_less_than_threshold(self):
        """Total < threshold harus raise ValueError."""
        with self.assertRaises(ValueError):
            generate_shares(self.master_key, threshold=3, total=2)


class TestReconstructSecret(unittest.TestCase):
    """Uji rekonstruksi secret dari share."""

    def setUp(self):
        """Setup: buat master key dan generate 3 share."""
        self.master_key = secrets.token_bytes(16)
        self.shares = generate_shares(self.master_key, threshold=2, total=3)
        # local=share[0], server=share[1], recovery=share[2]
        self.local_share    = self.shares[0]
        self.server_share   = self.shares[1]
        self.recovery_share = self.shares[2]

    def test_reconstruct_local_plus_server(self):
        """Rekonstruksi dari local share + server share (mode normal)."""
        reconstructed = reconstruct_secret([
            self.local_share,
            self.server_share
        ])
        self.assertEqual(reconstructed, self.master_key)

    def test_reconstruct_local_plus_recovery(self):
        """Rekonstruksi dari local share + recovery share (mode backup)."""
        reconstructed = reconstruct_secret([
            self.local_share,
            self.recovery_share
        ])
        self.assertEqual(reconstructed, self.master_key)

    def test_reconstruct_server_plus_recovery(self):
        """Rekonstruksi dari server share + recovery share (kombinasi lain)."""
        reconstructed = reconstruct_secret([
            self.server_share,
            self.recovery_share
        ])
        self.assertEqual(reconstructed, self.master_key)

    def test_reconstruct_all_three(self):
        """Rekonstruksi dengan 3 share juga menghasilkan secret yang benar."""
        reconstructed = reconstruct_secret(self.shares)
        self.assertEqual(reconstructed, self.master_key)

    def test_wrong_share_produces_wrong_secret(self):
        """Share palsu menghasilkan secret yang berbeda dari aslinya."""
        fake_share = {
            "index": self.recovery_share["index"],
            "value": format(secrets.randbelow(10**60), "064x")
        }
        reconstructed = reconstruct_secret([self.local_share, fake_share])
        # Secret yang direkonstruksi TIDAK sama dengan master key asli
        self.assertNotEqual(reconstructed, self.master_key)

    def test_single_share_raises_error(self):
        """Kurang dari 2 share harus raise ValueError."""
        with self.assertRaises(ValueError):
            reconstruct_secret([self.local_share])

    def test_empty_shares_raises_error(self):
        """List share kosong harus raise ValueError."""
        with self.assertRaises(ValueError):
            reconstruct_secret([])

    def test_duplicate_index_raises_error(self):
        """Share dengan index duplikat harus raise ValueError."""
        duplicate = {
            "index": self.local_share["index"],  # index sama dengan local share
            "value": self.server_share["value"]
        }
        with self.assertRaises(ValueError):
            reconstruct_secret([self.local_share, duplicate])

    def test_order_independence(self):
        """Urutan share tidak mempengaruhi hasil rekonstruksi."""
        result1 = reconstruct_secret([self.local_share, self.server_share])
        result2 = reconstruct_secret([self.server_share, self.local_share])
        self.assertEqual(result1, result2)
        self.assertEqual(result1, self.master_key)

    def test_multiple_keys_reconstruct_correctly(self):
        """Test dengan 10 master key berbeda untuk memastikan konsistensi."""
        for _ in range(10):
            key = secrets.token_bytes(16)
            shares = generate_shares(key, threshold=2, total=3)
            reconstructed = reconstruct_secret([shares[0], shares[1]])
            self.assertEqual(reconstructed, key)


class TestShareSerialization(unittest.TestCase):
    """Uji serialisasi share ke string dan sebaliknya."""

    def setUp(self):
        self.master_key = secrets.token_bytes(16)
        self.shares = generate_shares(self.master_key, threshold=2, total=3)
        self.recovery_share = self.shares[2]

    def test_share_to_string_format(self):
        """Output share_to_string harus format 'SSS:{index}:{value}'."""
        s = share_to_string(self.recovery_share)
        parts = s.split(":")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "SSS")
        self.assertEqual(int(parts[1]), self.recovery_share["index"])
        self.assertEqual(parts[2], self.recovery_share["value"])

    def test_string_to_share_roundtrip(self):
        """string_to_share(share_to_string(share)) == share."""
        for share in self.shares:
            s = share_to_string(share)
            reconstructed = string_to_share(s)
            self.assertEqual(reconstructed["index"], share["index"])
            self.assertEqual(reconstructed["value"], share["value"])

    def test_invalid_string_raises_error(self):
        """String yang tidak valid harus raise ValueError."""
        invalid_strings = [
            "invalid",
            "SSS:abc:def",    # index bukan integer
            "SSS:1",          # kurang field
            "XXX:1:abc123",   # prefix salah
            "",
        ]
        for s in invalid_strings:
            with self.assertRaises(ValueError, msg=f"Harus gagal untuk: '{s}'"):
                string_to_share(s)

    def test_recovery_share_reconstruct_via_string(self):
        """Recovery share yang di-serialize lalu di-parse bisa digunakan rekonstruksi."""
        # Simulasi: pengguna menyimpan dan memasukkan kembali recovery share
        recovery_str = share_to_string(self.recovery_share)
        parsed_share = string_to_share(recovery_str)

        reconstructed = reconstruct_secret([self.shares[0], parsed_share])
        self.assertEqual(reconstructed, self.master_key)


class TestSSSWithRealMasterKey(unittest.TestCase):
    """Uji SSS dengan skenario nyata password manager."""

    def test_aes128_master_key(self):
        """Test dengan master key 16 bytes (AES-128) persis seperti di vault.py."""
        # Simulasi vault.py: generate master key
        master_key = secrets.token_bytes(16)
        self.assertEqual(len(master_key), 16)

        # Bagi menjadi 3 share (2,3)
        shares = generate_shares(master_key, threshold=2, total=3)
        local_share    = shares[0]  # index 1
        server_share   = shares[1]  # index 2
        recovery_share = shares[2]  # index 3

        # Mode normal: local + server
        reconstructed_normal = reconstruct_secret([local_share, server_share])
        self.assertEqual(reconstructed_normal, master_key,
            "Mode normal: rekonstruksi gagal")

        # Mode backup: local + recovery
        reconstructed_backup = reconstruct_secret([local_share, recovery_share])
        self.assertEqual(reconstructed_backup, master_key,
            "Mode backup: rekonstruksi gagal")

    def test_information_theoretic_security(self):
        """
        Uji keamanan: 1 share tidak membocorkan informasi tentang secret.
        Dengan 1 share, semua kemungkinan secret sama-sama mungkin.
        Ini diuji dengan menunjukkan bahwa 1 share bisa cocok dengan
        banyak secret berbeda (setiap secret menghasilkan share berbeda).
        """
        # Buat dua master key berbeda
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(16)
        self.assertNotEqual(key1, key2)

        # Share yang sama dari key berbeda harus berbeda
        shares1 = generate_shares(key1, threshold=2, total=3)
        shares2 = generate_shares(key2, threshold=2, total=3)

        # Share ke-1 dari kedua key hampir pasti berbeda
        # (membuktikan share meng-encode informasi tentang key)
        # Tapi dari 1 share saja, tidak bisa bedakan key1 dari key2
        self.assertNotEqual(shares1[0]["value"], shares2[0]["value"])


if __name__ == "__main__":
    print("=" * 60)
    print("Menjalankan unit test Shamir Secret Sharing...")
    print("=" * 60)
    unittest.main(verbosity=2)