# SSS Vault - Distributed Password Manager CLI

Implementasi tugas 4 II4021 Kriptografi: password manager terdistribusi berbasis CLI dengan Shamir Secret Sharing, AES-GCM, KDF, CSPRNG, dan bonus kriptografi visual untuk recovery share.

## Tech Stack

- Python 3.11+
- Flask untuk server REST API
- SQLite untuk penyimpanan server
- `cryptography` untuk AES-GCM
- `argon2-cffi` untuk Argon2id KDF
- `requests` untuk komunikasi client-server
- `qrcode` dan `Pillow` untuk bonus visual secret sharing

## Fitur

- Vault dienkripsi sebagai satu kesatuan menggunakan AES-128-GCM.
- Master key 16 byte dibagi menjadi 3 share dengan Shamir Secret Sharing skema (2,3):
  - local share disimpan terenkripsi di klien
  - server share disimpan di server
  - recovery share ditampilkan ke pengguna
- Mode normal: local share + server share.
- Mode backup: local share + recovery share, read-only.
- CRUD password hanya di mode normal.
- Password generator memakai CSPRNG dari modul `secrets`.
- Bonus: recovery share dapat diubah menjadi QR code lalu dibagi menjadi dua visual shares.

## Instalasi

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Jika sudah ada `.venv`, cukup aktifkan environment tersebut.

## Menjalankan Program

Jalankan server terlebih dahulu:

```bash
.venv\Scripts\python.exe server\app.py
```

Di terminal lain, jalankan client CLI:

```bash
.venv\Scripts\python.exe client\main.py
```

Tampilan CLI akan membuka menu utama:

```text
+------------------------------------------------------------------+
|  SSS VAULT                                                       |
|  Distributed Password Manager CLI                                |
|  AES-128-GCM vault | Shamir (2,3) | Zero-knowledge server         |
+------------------------------------------------------------------+
```

## Konfigurasi

Server dapat dikonfigurasi lewat environment variable:

- `PM_HOST`, default `127.0.0.1`
- `PM_PORT`, default `5000`
- `PM_DEBUG`, default `false`
- `PM_DB_PATH`, default `server/pm_server.db`

Client memakai endpoint server pada [client/api_client.py](client/api_client.py).

## Struktur Penyimpanan

Data lokal klien disimpan di `client/local_data.json`:

- username
- local share terenkripsi
- nonce local share
- salt dan parameter KDF
- backup vault terenkripsi
- nonce backup vault

Data server disimpan di SQLite:

- username
- server share
- vault terenkripsi sebagai BLOB
- nonce vault
- metadata timestamp

Server tidak menyimpan master key, local share, recovery share, plaintext vault, password plaintext, atau kunci turunan KDF.

## Pengujian

Jalankan semua test:

```bash
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_*.py -v
```

Catatan penting: 9 pengujian pada instruksi tugas adalah 9 kategori/skenario minimum, bukan berarti wajib ada 9 file Python. Satu file test boleh memuat banyak skenario, dan satu skenario bisa diuji oleh beberapa test.

File test saat ini:

- `test_aes_gcm.py`: AES-128-GCM vault dan AES-256-GCM local share.
- `test_sss.py`: Shamir Secret Sharing dan format share.
- `test_kdf.py`: Argon2id KDF.
- `test_csprng.py`: password generator CSPRNG.
- `test_vault.py`: alur vault end-to-end dengan mock server.
- `test_assignment_requirements.py`: pemetaan eksplisit 9 kategori pengujian dari PDF.

Pemetaan 9 kategori dari instruksi:

| Kategori instruksi | Cakupan test |
| --- | --- |
| 1. Uji pembuatan vault | `TestRequirement01CreateVault`, `TestCreateVault` |
| 2. Uji perlindungan local share | `TestRequirement02LocalShareProtection`, `TestKDFIntegration` |
| 3. Uji akses normal | `TestRequirement03NormalAccess`, `TestOpenVaultNormal` |
| 4. Uji penambahan password | `TestRequirement04AddPassword`, `TestVaultCRUD` |
| 5. Uji pengubahan dan penghapusan | `TestRequirement05EditDeleteAndBackupReadOnly`, `TestVaultCRUD` |
| 6. Uji penyimpanan vault di server | `TestRequirement06ServerStorage`, `TestVaultSecurity` |
| 7. Uji mode backup | `TestRequirement07BackupMode`, `TestOpenVaultBackup` |
| 8. Uji kegagalan pemulihan | `TestRequirement08RecoveryFailures`, `TestVaultSecurity` |
| 9. Uji kriptografi visual bonus | `TestRequirement09VisualCryptographyBonus` |

Untuk laporan dan video demo, test otomatis dapat dijadikan bukti teknis. Namun beberapa poin "perlihatkan" tetap sebaiknya didemokan lewat CLI, misalnya recovery share yang tampil sekali, isi SQLite server, dan pemindaian QR hasil gabungan visual shares dengan kamera/QR scanner.
