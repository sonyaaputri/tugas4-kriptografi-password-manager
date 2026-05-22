-- ============================================================
-- Skema database SQLite untuk server Password Manager
-- ============================================================

-- Tabel utama pengguna
-- Menyimpan metadata pengguna dan server share
-- TIDAK menyimpan: master key, local share, recovery share,
--                  plaintext vault, password plaintext, kunci KDF
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identitas pengguna
    username    TEXT NOT NULL UNIQUE,

    -- Server share: salah satu dari 3 share hasil SSS
    -- Format JSON string: {"index": x, "value": "hex/base64"}
    -- Satu share saja tidak cukup untuk rekonstruksi master key
    server_share    TEXT NOT NULL,

    -- Vault terenkripsi sebagai BLOB (hasil AES-128-GCM di sisi klien)
    -- Server tidak pernah melihat isi plaintext vault
    vault_blob      BLOB,

    -- Nonce yang digunakan pada enkripsi vault terakhir (AES-128-GCM)
    -- Hex string, 12 bytes = 24 karakter hex
    vault_nonce     TEXT,

    -- Timestamp pembuatan dan pembaruan
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Catatan desain (zero-knowledge server):
--
-- 1. server_share hanya 1 dari 3 share SSS → tidak bisa rekonstruksi
--    master key tanpa minimal 1 share lain (local atau recovery)
--
-- 2. vault_blob adalah ciphertext AES-128-GCM → server tidak bisa
--    membaca isi vault tanpa master key
--
-- 3. vault_nonce wajib unik setiap enkripsi ulang →
--    klien selalu generate nonce baru setiap ada perubahan data
--
-- 4. Tidak ada kolom untuk: master key, local share, recovery share,
--    plaintext password, salt KDF, kunci turunan
-- ============================================================