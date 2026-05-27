# ============================================================
# Tampilan mode backup (server tidak aktif)
# ============================================================

import customtkinter as ctk
import json
import threading
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import local_storage as storage
import vault as vault_logic

COLORS = {
    "bg_dark":        "#0f1117",
    "bg_card":        "#1a1d27",
    "bg_input":       "#252836",
    "accent":         "#4f8ef7",
    "accent_hover":   "#3a7de0",
    "danger":         "#e05c5c",
    "success":        "#4caf7d",
    "text_primary":   "#f0f2f8",
    "text_secondary": "#8a8fa8",
    "border":         "#2e3146",
    "warning_bg":     "#2d2410",
    "warning_border": "#7a5c00",
    "warning_text":   "#f0c040",
}


class BackupView(ctk.CTkFrame):
    """
    Tampilan login mode backup.
    Membutuhkan master password + recovery share.
    Vault yang dibuka bersifat read-only.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS["bg_dark"], **kwargs)
        self.master = master
        self._build_ui()

    def _build_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        container = ctk.CTkFrame(
            self,
            fg_color=COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        container.grid(row=0, column=0, padx=60, pady=40, sticky="")
        container.grid_columnconfigure(0, weight=1)

        # Header
        ctk.CTkLabel(
            container,
            text="Mode Backup",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["warning_text"],
        ).grid(row=0, column=0, padx=40, pady=(36, 6))

        ctk.CTkLabel(
            container,
            text="Server tidak aktif. Masuk menggunakan recovery share (hanya baca).",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            wraplength=360,
            justify="center",
        ).grid(row=1, column=0, padx=40, pady=(0, 20))

        # Form
        ctk.CTkLabel(
            container, text="Master Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=32, pady=(0, 2))

        self._pass_entry = ctk.CTkEntry(
            container,
            placeholder_text="Masukkan master password",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
            width=360,
        )
        self._pass_entry.grid(row=3, column=0, padx=32, sticky="ew")

        ctk.CTkLabel(
            container, text="Recovery Share Index",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=4, column=0, sticky="w", padx=32, pady=(14, 2))

        self._index_entry = ctk.CTkEntry(
            container,
            placeholder_text="Contoh: 3",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._index_entry.grid(row=5, column=0, padx=32, sticky="ew")

        ctk.CTkLabel(
            container, text="Recovery Share Value",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=6, column=0, sticky="w", padx=32, pady=(14, 2))

        self._value_entry = ctk.CTkEntry(
            container,
            placeholder_text="Tempelkan nilai recovery share di sini",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._value_entry.grid(row=7, column=0, padx=32, sticky="ew")

        self._status_label = ctk.CTkLabel(
            container, text="",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["danger"],
            wraplength=340,
        )
        self._status_label.grid(row=8, column=0, padx=32, pady=(10, 0))

        # Tombol
        self._open_btn = ctk.CTkButton(
            container,
            text="Buka Vault (Hanya Baca)",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=44,
            corner_radius=8,
            command=self._do_open_backup,
        )
        self._open_btn.grid(row=9, column=0, padx=32, pady=(16, 10), sticky="ew")

        ctk.CTkButton(
            container,
            text="Kembali ke Login",
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            hover_color=COLORS["bg_input"],
            height=34,
            corner_radius=8,
            command=self.master.goto_login,
        ).grid(row=10, column=0, padx=32, pady=(0, 28), sticky="ew")

    def _set_status(self, text: str, is_error: bool = True):
        color = COLORS["danger"] if is_error else COLORS["success"]
        self._status_label.configure(text=text, text_color=color)

    def _do_open_backup(self):
        password    = self._pass_entry.get()
        index_str   = self._index_entry.get().strip()
        share_value = self._value_entry.get().strip()

        if not password:
            self._set_status("Master password tidak boleh kosong.")
            return
        if not index_str or not share_value:
            self._set_status("Index dan value recovery share wajib diisi.")
            return

        try:
            index = int(index_str)
        except ValueError:
            self._set_status("Index harus berupa angka.")
            return

        recovery_share = {"index": index, "value": share_value}

        self._open_btn.configure(text="Memproses...", state="disabled")
        self._set_status("")

        def worker():
            vault = vault_logic.open_vault_backup(password, recovery_share)
            self.after(0, lambda: self._on_done(vault, password))

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, vault, password):
        self._open_btn.configure(text="Buka Vault (Hanya Baca)", state="normal")
        if vault is None:
            self._set_status(
                "Gagal membuka vault. Periksa master password dan recovery share."
            )
            return

        username = storage.get_username() or ""
        self.master.session["username"]        = username
        self.master.session["master_password"] = password
        self.master.session["vault"]           = vault
        self.master.session["mode"]            = "backup"
        self.master.goto_vault()
