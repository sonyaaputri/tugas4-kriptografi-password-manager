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

## Dependensi

Seluruh dependensi Python dicantumkan pada [requirements.txt](requirements.txt).
Dependensi utama:

- `Flask`
- `cryptography`
- `argon2-cffi`
- `requests`
- `qrcode`
- `Pillow`

## Fitur Utama

- Vault dienkripsi sebagai satu kesatuan menggunakan AES-128-GCM.
- Master key 16 byte dibagi menjadi 3 share dengan Shamir Secret Sharing skema (2,3):
  - local share disimpan terenkripsi di klien
  - server share disimpan di server
  - recovery share ditampilkan ke pengguna
- Mode normal: local share + server share.
- Mode backup: local share + recovery share, read-only.
- CRUD password hanya di mode normal.
- Data lokal klien disimpan per username sehingga satu client dapat menyimpan beberapa vault lokal.
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

Tampilan CLI akan membuka welcome screen dan menu awal:

```text
MAIN MENU
  [1] Masuk ke vault
  [2] Buat vault baru
  [3] Alat bantu
  [0] Keluar
```

Alur "Buat vault baru" berperan seperti signup. Alur "Masuk ke vault"
berperan seperti login lokal: pengguna memasukkan username dan master
password, lalu client membuka local share milik username tersebut.
Master password tidak dikirim ke server.

## Konfigurasi

Server dapat dikonfigurasi lewat environment variable:

- `PM_HOST`, default `127.0.0.1`
- `PM_PORT`, default `5000`
- `PM_DEBUG`, default `false`
- `PM_DB_PATH`, default `server/pm_server.db`

Client memakai endpoint server pada [client/api_client.py](client/api_client.py).

## Struktur Penyimpanan

Data lokal klien disimpan per username di `client/local_users/`. Contoh path:
`client/local_users/<username-terenkode>.json`.

Data lokal memuat:

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

Artefak bonus visual secret sharing disimpan secara default di:

- `client/recovery_artifacts/<username>/` jika dibuat dari sesi vault
- `client/recovery_artifacts/manual/` jika dibuat dari menu alat bantu awal

## Pengujian

Jalankan semua test:

```bash
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_*.py -v
```

File test :

- `test_aes_gcm.py`: AES-128-GCM vault dan AES-256-GCM local share.
- `test_sss.py`: Shamir Secret Sharing dan format share.
- `test_kdf.py`: Argon2id KDF.
- `test_csprng.py`: password generator CSPRNG.
- `test_vault.py`: alur vault end-to-end dengan mock server.
- `test_assignment_requirements.py`: pemetaan eksplisit 9 kategori pengujian dari PDF.

9 kategori pengujian program:

| Kategori pengujian | Cakupan test |
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

## Credits

Project ini dibuat untuk memenuhi Tugas 4 II4021 Kriptografi.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/snachkzs">
        <img src="https://github.com/snachkzs.png" width="80" style="border-radius: 50%"><br/>
        <strong>Alma Felicia Vielrizki</strong><br/>
        18223112
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/sonyaaputri">
        <img src="https://github.com/sonyaaputri.png" width="80" style="border-radius: 50%"><br/>
        <strong>Sonya Putri Fadilah</strong><br/>
        18223138
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/auliaazkaazzahra">
        <img src="https://github.com/auliaazkaazzahra.png" width="80" style="border-radius: 50%"><br/>
        <strong>Aulia Azka Azzahra</strong><br/>
        18223131
      </a>
    </td>  
  </tr>
</table>
