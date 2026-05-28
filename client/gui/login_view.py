import customtkinter as ctk
import threading
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import local_storage as storage
import api_client as api
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
}


class LoginView(ctk.CTkFrame):
    """
    Tampilan awal: login atau registrasi pengguna.
    - Jika data lokal ada, tampilkan form login normal + tombol backup.
    - Jika belum ada, tampilkan form registrasi.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS["bg_dark"], **kwargs)
        self.master = master
        self._has_local = storage.local_data_exists()
        self._build_ui()

    def _build_ui(self):
        # Layout utama: tengah halaman
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        container = ctk.CTkFrame(
            self,
            fg_color=COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        container.grid(row=0, column=0, padx=40, pady=40, sticky="")
        container.grid_columnconfigure(0, weight=1)

        # Judul
        title_text = "Password Manager"
        ctk.CTkLabel(
            container,
            text=title_text,
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, padx=40, pady=(36, 4))

        ctk.CTkLabel(
            container,
            text="Simpan kata sandi dengan enkripsi AES-128-GCM",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
        ).grid(row=1, column=0, padx=40, pady=(0, 28))

        # Tab: Login / Daftar
        self._tab_view = ctk.CTkTabview(
            container,
            width=360,
            fg_color=COLORS["bg_card"],
            segmented_button_fg_color=COLORS["bg_input"],
            segmented_button_selected_color=COLORS["accent"],
            segmented_button_selected_hover_color=COLORS["accent"],
            segmented_button_unselected_color=COLORS["bg_input"],
            segmented_button_unselected_hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
        )
        self._tab_view.grid(row=2, column=0, padx=24, pady=(0, 8))

        if self._has_local:
            self._tab_view.add("Masuk")
            self._build_login_tab(self._tab_view.tab("Masuk"))
        else:
            self._tab_view.add("Daftar")
            self._build_register_tab(self._tab_view.tab("Daftar"))

        # Tombol mode backup (hanya jika ada data lokal)
        if self._has_local:
            ctk.CTkButton(
                container,
                text="Masuk dengan Mode Backup",
                font=ctk.CTkFont(size=12),
                fg_color="transparent",
                text_color=COLORS["text_secondary"],
                hover_color=COLORS["bg_input"],
                height=30,
                command=self._go_backup,
            ).grid(row=3, column=0, padx=40, pady=(0, 20))
        else:
            ctk.CTkFrame(container, height=20, fg_color="transparent").grid(row=3, column=0)

        # Label status
        self._status_label = ctk.CTkLabel(
            container,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["danger"],
            wraplength=340,
        )
        self._status_label.grid(row=4, column=0, padx=24, pady=(0, 20))

    def _build_login_tab(self, parent):
        """Form login normal."""
        parent.grid_columnconfigure(0, weight=1)

        username = storage.get_username() or ""

        ctk.CTkLabel(
            parent, text="Username",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(12, 2))

        self._login_user_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Masukkan username",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._login_user_entry.grid(row=1, column=0, sticky="ew", padx=4)
        if username:
            self._login_user_entry.insert(0, username)

        ctk.CTkLabel(
            parent, text="Master Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=4, pady=(12, 2))

        self._login_pass_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Masukkan master password",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._login_pass_entry.grid(row=3, column=0, sticky="ew", padx=4)
        self._login_pass_entry.bind("<Return>", lambda e: self._do_login())

        self._login_btn = ctk.CTkButton(
            parent,
            text="Masuk",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=42,
            corner_radius=8,
            command=self._do_login,
        )
        self._login_btn.grid(row=4, column=0, sticky="ew", padx=4, pady=(18, 12))

    def _build_register_tab(self, parent):
        """Form registrasi pengguna baru."""
        parent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            parent, text="Username",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(12, 2))

        self._reg_user_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Pilih username unik",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._reg_user_entry.grid(row=1, column=0, sticky="ew", padx=4)

        ctk.CTkLabel(
            parent, text="Master Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=4, pady=(12, 2))

        self._reg_pass_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Buat master password kuat",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._reg_pass_entry.grid(row=3, column=0, sticky="ew", padx=4)

        ctk.CTkLabel(
            parent, text="Konfirmasi Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=4, column=0, sticky="w", padx=4, pady=(12, 2))

        self._reg_confirm_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Ulangi master password",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._reg_confirm_entry.grid(row=5, column=0, sticky="ew", padx=4)
        self._reg_confirm_entry.bind("<Return>", lambda e: self._do_register())

        self._reg_btn = ctk.CTkButton(
            parent,
            text="Buat Vault",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=42,
            corner_radius=8,
            command=self._do_register,
        )
        self._reg_btn.grid(row=6, column=0, sticky="ew", padx=4, pady=(18, 12))

    def _set_status(self, text: str, is_error: bool = True):
        color = COLORS["danger"] if is_error else COLORS["success"]
        self._status_label.configure(text=text, text_color=color)

    def _set_loading(self, widget, loading: bool, original_text: str):
        if loading:
            widget.configure(text="Memproses...", state="disabled")
        else:
            widget.configure(text=original_text, state="normal")

    def _do_login(self):
        username = self._login_user_entry.get().strip()
        password = self._login_pass_entry.get()

        if not username or not password:
            self._set_status("Username dan password tidak boleh kosong.")
            return

        self._set_loading(self._login_btn, True, "Masuk")
        self._set_status("")

        def worker():
            vault = vault_logic.open_vault_normal(password)
            self.after(0, lambda: self._on_login_done(vault, username, password))

        threading.Thread(target=worker, daemon=True).start()

    def _on_login_done(self, vault, username, password):
        self._set_loading(self._login_btn, False, "Masuk")
        if vault is None:
            self._set_status(
                "Login gagal. Periksa master password atau koneksi ke server."
            )
            return

        self.master.session["username"]        = username
        self.master.session["master_password"] = password
        self.master.session["vault"]           = vault
        self.master.session["mode"]            = "normal"
        self.master.goto_vault()

    def _do_register(self):
        username = self._reg_user_entry.get().strip()
        password = self._reg_pass_entry.get()
        confirm  = self._reg_confirm_entry.get()

        if not username:
            self._set_status("Username tidak boleh kosong.")
            return
        if len(password) < 8:
            self._set_status("Master password minimal 8 karakter.")
            return
        if password != confirm:
            self._set_status("Konfirmasi password tidak cocok.")
            return

        if not api.is_server_online():
            self._set_status("Server tidak dapat diakses. Pastikan server berjalan.")
            return

        self._set_loading(self._reg_btn, True, "Buat Vault")
        self._set_status("")

        def worker():
            recovery_share = vault_logic.create_vault(username, password)
            self.after(0, lambda: self._on_register_done(recovery_share, username, password))

        threading.Thread(target=worker, daemon=True).start()

    def _on_register_done(self, recovery_share, username, password):
        self._set_loading(self._reg_btn, False, "Buat Vault")
        if recovery_share is None:
            self._set_status("Registrasi gagal. Username mungkin sudah dipakai.")
            return

        self.master.session["username"]        = username
        self.master.session["master_password"] = password
        self.master.session["vault"]           = []
        self.master.session["mode"]            = "normal"
        self.master.goto_recovery(recovery_share)

    def _go_backup(self):
        self.master.goto_backup_login()
