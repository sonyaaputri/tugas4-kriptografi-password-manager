from __future__ import annotations

import getpass
import os
from typing import Callable

import api_client as api
import local_storage as storage
import vault as vault_logic
from crypto.csprng import generate_password
from crypto.sss import share_to_string, string_to_share


BANNER = r"""
+------------------------------------------------------------------+
|  SSS VAULT                                                       |
|  Distributed Password Manager CLI                                |
|  AES-128-GCM vault | Shamir (2,3) | Zero-knowledge server         |
+------------------------------------------------------------------+
"""


ACTION_LABELS = {
    "list": "Lihat daftar password",
    "search": "Cari password",
    "detail": "Lihat detail password",
    "add": "Tambah password",
    "edit": "Ubah password",
    "delete": "Hapus password",
    "generate": "Generate password CSPRNG",
    "logout": "Keluar dari vault",
}


def available_vault_actions(mode: str) -> list[str]:
    """Return CLI actions allowed for a vault session mode."""
    actions = ["list", "search", "detail"]
    if mode == "normal":
        actions.extend(["add", "edit", "delete"])
    actions.extend(["generate", "logout"])
    return actions


class PasswordManagerCLI:
    def __init__(
        self,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
    ) -> None:
        self._input = input_func
        self._print = output_func

    def run(self) -> None:
        while True:
            self._print_banner()
            self._print(f"Local user : {storage.get_username() or '-'}")
            self._print(f"Server     : {'online' if api.is_server_online() else 'offline'}")
            self._print("")
            self._print("Menu utama")
            self._print("  1. Buat vault baru")
            self._print("  2. Buka vault mode normal")
            self._print("  3. Buka vault mode backup")
            self._print("  4. Generate password CSPRNG")
            self._print("  5. Bonus: buat QR dan visual shares")
            self._print("  6. Bonus: gabungkan visual shares")
            self._print("  0. Keluar")

            choice = self._ask("Pilih menu")
            if choice == "1":
                self._register_flow()
            elif choice == "2":
                self._normal_login_flow()
            elif choice == "3":
                self._backup_login_flow()
            elif choice == "4":
                self._generate_password_flow()
            elif choice == "5":
                self._visual_share_flow()
            elif choice == "6":
                self._combine_visual_share_flow()
            elif choice == "0":
                self._print("Sampai jumpa.")
                return
            else:
                self._warn("Pilihan tidak dikenal.")
            self._pause()

    def _register_flow(self) -> None:
        self._section("Buat Vault Baru")

        if not api.is_server_online():
            self._warn("Server tidak dapat diakses. Jalankan server sebelum membuat vault.")
            return

        if storage.local_data_exists():
            self._warn("Data lokal sudah ada. Membuat vault baru akan mengganti local share lokal.")
            if not self._confirm("Lanjutkan"):
                return

        username = self._ask_nonempty("Username")
        master_password = self._ask_new_master_password()
        if master_password is None:
            return

        recovery_share = vault_logic.create_vault(username, master_password)
        if recovery_share is None:
            self._warn("Registrasi gagal. Username mungkin sudah dipakai di server.")
            return

        recovery_text = share_to_string(recovery_share)
        self._ok("Vault berhasil dibuat.")
        self._print("")
        self._print("Ringkasan kriptografi")
        self._print("  [OK] Master key AES-128 berhasil dibangkitkan secara acak (16 bytes).")
        self._print("  [OK] Vault kosong berhasil dienkripsi dengan AES-128-GCM.")
        self._print("  [OK] Master key dibagi menjadi 3 share dengan SSS skema (2,3).")
        self._print("  [OK] Local share disimpan terenkripsi di klien.")
        self._print("  [OK] Server hanya menerima server share, vault terenkripsi, nonce, dan metadata.")
        self._print("")
        self._print("RECOVERY SHARE - SIMPAN SEKARANG")
        self._print("+------------------------------------------------------------------+")
        self._print(recovery_text)
        self._print("+------------------------------------------------------------------+")
        self._print("Recovery share ini memuat koordinat share dan nilai share.")

        if self._confirm("Buat QR dan visual shares untuk recovery share"):
            output_dir = self._ask(
                "Folder output",
                default=self._default_recovery_artifacts_dir(),
            )
            self._create_visual_shares(recovery_text, output_dir)

        self._print("")
        if self._confirm("Masuk ke vault sekarang"):
            self._vault_menu({
                "mode": "normal",
                "vault": [],
                "master_password": master_password,
            })

    def _normal_login_flow(self) -> None:
        self._section("Mode Normal")
        if not storage.local_data_exists():
            self._warn("Data lokal belum ada. Buat vault terlebih dahulu.")
            return
        if not api.is_server_online():
            self._warn("Server offline. Gunakan mode backup untuk akses darurat.")
            return

        username = storage.get_username() or "-"
        self._print(f"Local user: {username}")
        master_password = getpass.getpass("Master password: ")
        vault = vault_logic.open_vault_normal(master_password)
        if vault is None:
            self._warn("Akses ditolak. Password salah, server bermasalah, atau vault tidak valid.")
            return

        self._ok("Vault berhasil dibuka dengan local share + server share.")
        self._vault_menu({
            "mode": "normal",
            "vault": vault,
            "master_password": master_password,
        })

    def _backup_login_flow(self) -> None:
        self._section("Mode Backup")
        if not storage.local_data_exists():
            self._warn("Data lokal belum ada.")
            return
        if not storage.backup_exists():
            self._warn("Backup vault lokal belum tersedia.")
            return

        self._print("Mode backup bersifat read-only.")
        master_password = getpass.getpass("Master password: ")
        recovery_share = self._read_recovery_share()
        if recovery_share is None:
            return

        vault = vault_logic.open_vault_backup(master_password, recovery_share)
        if vault is None:
            self._warn("Akses backup gagal. Password, recovery share, atau backup vault tidak valid.")
            return

        self._ok("Vault berhasil dibuka dengan local share + recovery share.")
        self._vault_menu({
            "mode": "backup",
            "vault": vault,
            "master_password": master_password,
        })

    def _vault_menu(self, session: dict) -> None:
        mode = session["mode"]
        actions = available_vault_actions(mode)

        while True:
            self._section(f"Vault Mode {mode.upper()}")
            self._print(f"Isi vault: {len(session['vault'])} password")
            if mode == "backup":
                self._print("[READ-ONLY] Tambah, ubah, dan hapus dinonaktifkan.")
            self._print("")

            for number, action in enumerate(actions, start=1):
                self._print(f"  {number}. {ACTION_LABELS[action]}")

            choice = self._ask("Pilih aksi")
            try:
                action = actions[int(choice) - 1]
            except (ValueError, IndexError):
                self._warn("Pilihan tidak valid.")
                self._pause()
                continue

            if action == "list":
                self._list_entries(session["vault"])
            elif action == "search":
                self._search_entries(session["vault"])
            elif action == "detail":
                self._show_entry_detail(session["vault"])
            elif action == "add":
                self._add_entry(session)
            elif action == "edit":
                self._edit_entry(session)
            elif action == "delete":
                self._delete_entry(session)
            elif action == "generate":
                self._generate_password_flow()
            elif action == "logout":
                session["master_password"] = None
                self._ok("Keluar dari vault.")
                return
            self._pause()

    def _list_entries(self, vault: list[dict], rows: list[tuple[int, dict]] | None = None) -> None:
        rows = rows if rows is not None else list(enumerate(vault))
        if not rows:
            self._print("Vault kosong.")
            return

        self._print("+----+----------------------+----------------------+--------------+")
        self._print("| No | Layanan              | Username             | Password     |")
        self._print("+----+----------------------+----------------------+--------------+")
        for index, entry in rows:
            self._print(
                f"| {index + 1:>2} | "
                f"{self._clip(entry.get('nama_layanan', ''), 20):<20} | "
                f"{self._clip(entry.get('username', ''), 20):<20} | "
                f"{'********':<12} |"
            )
        self._print("+----+----------------------+----------------------+--------------+")

    def _search_entries(self, vault: list[dict]) -> None:
        keyword = self._ask_nonempty("Kata kunci")
        keyword_lower = keyword.lower()
        rows = [
            (index, entry)
            for index, entry in enumerate(vault)
            if keyword_lower in entry.get("nama_layanan", "").lower()
            or keyword_lower in entry.get("username", "").lower()
        ]
        self._list_entries(vault, rows)

    def _show_entry_detail(self, vault: list[dict]) -> None:
        index = self._ask_index(vault)
        if index is None:
            return
        entry = vault[index]
        self._print("")
        self._print("+---------------- Detail Password ----------------+")
        self._print(f"Layanan  : {entry.get('nama_layanan', '')}")
        self._print(f"Username : {entry.get('username', '')}")
        self._print(f"Password : {entry.get('password', '')}")
        self._print(f"Catatan  : {entry.get('catatan', '')}")
        self._print("+-------------------------------------------------+")

    def _add_entry(self, session: dict) -> None:
        self._section("Tambah Password")
        layanan = self._ask_nonempty("Nama layanan")
        username = self._ask_nonempty("Username/email")
        password = self._ask_password_value()
        catatan = self._ask("Catatan", default="")

        new_vault = vault_logic.add_entry(
            session["vault"],
            session["master_password"],
            layanan,
            username,
            password,
            catatan,
        )
        if new_vault is None:
            self._warn("Gagal menyimpan. Periksa server atau master password.")
            return

        session["vault"] = new_vault
        self._ok("Password ditambahkan. Vault dan backup lokal sudah diperbarui.")

    def _edit_entry(self, session: dict) -> None:
        self._section("Ubah Password")
        index = self._ask_index(session["vault"])
        if index is None:
            return

        old = session["vault"][index]
        layanan = self._ask("Nama layanan", default=old.get("nama_layanan", ""))
        username = self._ask("Username/email", default=old.get("username", ""))
        password_choice = self._ask(
            "Password baru (kosong=pakai lama, g=generate)",
            default="",
        )
        if password_choice.lower() == "g":
            password = self._generate_password_flow(return_value=True)
        elif password_choice == "":
            password = old.get("password", "")
        else:
            password = password_choice
        catatan = self._ask("Catatan", default=old.get("catatan", ""))

        new_vault = vault_logic.edit_entry(
            session["vault"],
            session["master_password"],
            index,
            nama_layanan=layanan,
            username=username,
            password=password,
            catatan=catatan,
        )
        if new_vault is None:
            self._warn("Gagal menyimpan perubahan.")
            return

        session["vault"] = new_vault
        self._ok("Password berhasil diubah dan vault dienkripsi ulang.")

    def _delete_entry(self, session: dict) -> None:
        self._section("Hapus Password")
        index = self._ask_index(session["vault"])
        if index is None:
            return

        entry = session["vault"][index]
        if not self._confirm(f"Hapus password untuk {entry.get('nama_layanan', '')}"):
            return

        new_vault = vault_logic.delete_entry(
            session["vault"],
            session["master_password"],
            index,
        )
        if new_vault is None:
            self._warn("Gagal menghapus password.")
            return

        session["vault"] = new_vault
        self._ok("Password dihapus dan vault dienkripsi ulang.")

    def _generate_password_flow(self, return_value: bool = False) -> str:
        self._section("Generate Password CSPRNG")
        while True:
            try:
                length = int(self._ask("Panjang password", default="16"))
                if 4 <= length <= 128:
                    break
                self._warn("Panjang harus antara 4 dan 128.")
            except ValueError:
                self._warn("Masukkan angka yang valid.")

        self._print("Kategori karakter")
        use_upper = self._confirm("Gunakan huruf besar A-Z", default=True)
        use_lower = self._confirm("Gunakan huruf kecil a-z", default=True)
        use_digits = self._confirm("Gunakan angka 0-9", default=True)
        use_symbols = self._confirm("Gunakan simbol", default=True)

        try:
            password = generate_password(
                length,
                use_uppercase=use_upper,
                use_lowercase=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols,
            )
        except ValueError as exc:
            self._warn(str(exc))
            return self._generate_password_flow(return_value=return_value)

        self._ok(f"Password {length} karakter berhasil dibuat.")
        self._print(password)
        return password if return_value else ""

    def _visual_share_flow(self) -> None:
        self._section("Bonus Visual Secret Sharing")
        recovery_share = self._ask_nonempty("Recovery share (SSS:index:value)")
        try:
            parsed = string_to_share(recovery_share)
            recovery_share = share_to_string(parsed)
        except ValueError as exc:
            self._warn(str(exc))
            return

        output_dir = self._ask(
            "Folder output",
            default=self._default_recovery_artifacts_dir(),
        )
        self._create_visual_shares(recovery_share, output_dir)

    def _combine_visual_share_flow(self) -> None:
        self._section("Gabungkan Visual Shares")
        share1_path = self._ask_nonempty("Path visual_share1.png")
        share2_path = self._ask_nonempty("Path visual_share2.png")
        default_output_dir = os.path.dirname(share1_path)
        default_output = (
            os.path.join(default_output_dir, "reconstructed_qr.png")
            if default_output_dir
            else "reconstructed_qr.png"
        )
        output_path = self._ask("Path output", default=default_output)
        try:
            from crypto.visual_secret import reconstruct_and_verify

            result = reconstruct_and_verify(share1_path, share2_path, output_path)
            self._ok(f"QR hasil gabungan disimpan di: {result}")
        except Exception as exc:
            self._warn(f"Gagal menggabungkan visual shares: {exc}")

    def _create_visual_shares(self, recovery_share: str, output_dir: str) -> None:
        try:
            from crypto.visual_secret import create_visual_shares

            qr_path, share1_path, share2_path = create_visual_shares(
                recovery_share,
                output_dir=output_dir,
            )
            self._ok("Artefak visual recovery berhasil dibuat.")
            self._print(f"  QR awal        : {qr_path}")
            self._print(f"  Visual share 1 : {share1_path}")
            self._print(f"  Visual share 2 : {share2_path}")
        except Exception as exc:
            self._warn(f"Fitur visual secret belum bisa dijalankan: {exc}")

    def _default_recovery_artifacts_dir(self) -> str:
        username = storage.get_username()
        base_dir = os.path.join("client", "recovery_artifacts")
        return os.path.join(base_dir, username) if username else base_dir

    def _read_recovery_share(self) -> dict | None:
        self._print("Masukkan recovery share dalam format SSS:3:<hex>.")
        self._print("Jika hanya punya index dan value terpisah, kosongkan input pertama.")
        raw = self._ask("Recovery share", default="")
        if raw:
            try:
                return string_to_share(raw)
            except ValueError as exc:
                self._warn(str(exc))
                return None

        try:
            index = int(self._ask_nonempty("Index"))
            value = self._ask_nonempty("Value hex")
            return {"index": index, "value": value}
        except ValueError:
            self._warn("Index harus berupa angka.")
            return None

    def _ask_password_value(self) -> str:
        self._print("Password untuk layanan")
        self._print("  1. Input manual")
        self._print("  2. Generate otomatis dengan CSPRNG")
        while True:
            choice = self._ask("Pilih metode", default="1")
            if choice == "1":
                password = getpass.getpass("Password layanan: ")
                if password:
                    return password
                self._warn("Password tidak boleh kosong.")
            elif choice == "2":
                return self._generate_password_flow(return_value=True)
            else:
                self._warn("Pilihan tidak valid.")

    def _ask_new_master_password(self) -> str | None:
        while True:
            password = getpass.getpass("Master password baru: ")
            if len(password) < 8:
                self._warn("Master password minimal 8 karakter.")
                continue
            confirm = getpass.getpass("Konfirmasi master password: ")
            if password != confirm:
                self._warn("Konfirmasi tidak cocok.")
                continue
            return password

    def _ask_index(self, vault: list[dict]) -> int | None:
        if not vault:
            self._warn("Vault kosong.")
            return None
        self._list_entries(vault)
        try:
            index = int(self._ask("Nomor entry")) - 1
        except ValueError:
            self._warn("Nomor harus berupa angka.")
            return None
        if index < 0 or index >= len(vault):
            self._warn("Nomor entry tidak valid.")
            return None
        return index

    def _print_banner(self) -> None:
        self._print(BANNER)

    def _section(self, title: str) -> None:
        self._print("")
        self._print("=" * 66)
        self._print(title.upper())
        self._print("=" * 66)

    def _ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        value = self._input(f"{prompt}{suffix}: ").strip()
        if value == "" and default is not None:
            return default
        return value

    def _ask_nonempty(self, prompt: str) -> str:
        while True:
            value = self._ask(prompt)
            if value:
                return value
            self._warn("Input tidak boleh kosong.")

    def _confirm(self, prompt: str, default: bool = False) -> bool:
        marker = "Y/n" if default else "y/N"
        value = self._input(f"{prompt}? [{marker}]: ").strip().lower()
        if value == "":
            return default
        return value in {"y", "yes", "ya"}

    def _pause(self) -> None:
        self._input("\nTekan Enter untuk lanjut...")

    def _ok(self, message: str) -> None:
        self._print(f"[OK] {message}")

    def _warn(self, message: str) -> None:
        self._print(f"[!] {message}")

    @staticmethod
    def _clip(value: str, width: int) -> str:
        value = value.replace("\n", " ")
        if len(value) <= width:
            return value
        return value[: max(0, width - 3)] + "..."
