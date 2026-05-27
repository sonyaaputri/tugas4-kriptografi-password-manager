import customtkinter as ctk
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import local_storage as storage
import api_client as api

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg_dark":       "#0f1117",
    "bg_card":       "#1a1d27",
    "bg_input":      "#252836",
    "accent":        "#4f8ef7",
    "accent_hover":  "#3a7de0",
    "danger":        "#e05c5c",
    "danger_hover":  "#c94444",
    "success":       "#4caf7d",
    "text_primary":  "#f0f2f8",
    "text_secondary":"#8a8fa8",
    "border":        "#2e3146",
}


class App(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("860x600")
        self.minsize(700, 520)
        self.configure(fg_color=COLORS["bg_dark"])

        # State sesi pengguna
        self.session = {
            "username":        None,
            "master_password": None,
            "vault":           None,
            "mode":            None,   # "normal" | "backup"
        }

        self.current_frame = None

        self._start()

    def _start(self):
        """Menentukan tampilan awal berdasarkan data lokal."""
        from gui.login_view import LoginView
        self.show_frame(LoginView)

    def show_frame(self, FrameClass, **kwargs):
        """Mengganti tampilan aktif dengan frame baru."""
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = FrameClass(self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def goto_login(self):
        """Kembali ke halaman login dan bersihkan sesi."""
        self.session = {
            "username":        None,
            "master_password": None,
            "vault":           None,
            "mode":            None,
        }
        from gui.login_view import LoginView
        self.show_frame(LoginView)

    def goto_vault(self):
        """Buka halaman daftar password (vault)."""
        from gui.vault_view import VaultView
        self.show_frame(VaultView)

    def goto_recovery(self, recovery_share: dict):
        """Tampilkan halaman recovery share setelah registrasi."""
        from gui.recovery_view import RecoveryView
        self.show_frame(RecoveryView, recovery_share=recovery_share)

    def goto_backup_login(self):
        """Buka halaman login mode backup."""
        from gui.backup_view import BackupView
        self.show_frame(BackupView)
