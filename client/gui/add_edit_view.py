import customtkinter as ctk
import threading
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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


class AddEditDialog(ctk.CTkToplevel):

    def __init__(self, parent, mode: str, index: int = -1, entry: dict = None):
        """
        parent : VaultView
        mode   : "add" atau "edit"
        index  : index entri yang diedit (hanya untuk mode edit)
        entry  : data entri yang diedit (hanya untuk mode edit)
        """
        super().__init__(parent)
        self._parent  = parent
        self._mode    = mode
        self._index   = index
        self._entry   = entry or {}

        title = "Tambah Password" if mode == "add" else "Edit Password"
        self.title(title)
        self.geometry("440x440")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_card"])
        self.grab_set()

        self._build_ui(title)

    def _build_ui(self, title: str):
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, padx=32, pady=(28, 4))

        # Layanan
        ctk.CTkLabel(
            self, text="Nama Layanan / Website",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=32, pady=(16, 2))

        self._layanan_entry = ctk.CTkEntry(
            self,
            placeholder_text="Contoh: Google, GitHub",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._layanan_entry.grid(row=2, column=0, sticky="ew", padx=32)
        if self._entry.get("nama_layanan"):
            self._layanan_entry.insert(0, self._entry["nama_layanan"])

        # Username
        ctk.CTkLabel(
            self, text="Username / Email",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=3, column=0, sticky="w", padx=32, pady=(12, 2))

        self._username_entry = ctk.CTkEntry(
            self,
            placeholder_text="Contoh: user@email.com",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._username_entry.grid(row=4, column=0, sticky="ew", padx=32)
        if self._entry.get("username"):
            self._username_entry.insert(0, self._entry["username"])

        # Password
        ctk.CTkLabel(
            self, text="Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=5, column=0, sticky="w", padx=32, pady=(12, 2))

        self._password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Password untuk layanan ini",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._password_entry.grid(row=6, column=0, sticky="ew", padx=32)
        if self._entry.get("password"):
            self._password_entry.insert(0, self._entry["password"])

        # Catatan
        ctk.CTkLabel(
            self, text="Catatan (opsional)",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=7, column=0, sticky="w", padx=32, pady=(12, 2))

        self._catatan_entry = ctk.CTkEntry(
            self,
            placeholder_text="Catatan tambahan",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._catatan_entry.grid(row=8, column=0, sticky="ew", padx=32)
        if self._entry.get("catatan"):
            self._catatan_entry.insert(0, self._entry["catatan"])

        # Status
        self._status_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["danger"],
        )
        self._status_label.grid(row=9, column=0, padx=32, pady=(8, 0))

        # Tombol
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=10, column=0, padx=32, pady=(12, 28), sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_frame,
            text="Batal",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            height=40,
            corner_radius=8,
            command=self.destroy,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))

        save_text = "Tambah" if self._mode == "add" else "Simpan"
        self._save_btn = ctk.CTkButton(
            btn_frame,
            text=save_text,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=40,
            corner_radius=8,
            command=self._do_save,
        )
        self._save_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

    def _do_save(self):
        layanan  = self._layanan_entry.get().strip()
        username = self._username_entry.get().strip()
        password = self._password_entry.get()
        catatan  = self._catatan_entry.get().strip()

        if not layanan:
            self._status_label.configure(text="Nama layanan tidak boleh kosong.")
            return
        if not username:
            self._status_label.configure(text="Username tidak boleh kosong.")
            return
        if not password:
            self._status_label.configure(text="Password tidak boleh kosong.")
            return

        self._save_btn.configure(text="Menyimpan...", state="disabled")
        self._status_label.configure(text="")

        master_password = self._parent.master.session.get("master_password")
        vault_data      = self._parent._vault

        def worker():
            if self._mode == "add":
                new_vault = vault_logic.add_entry(
                    vault_data, master_password,
                    layanan, username, password, catatan,
                )
            else:
                new_vault = vault_logic.edit_entry(
                    vault_data, master_password, self._index,
                    nama_layanan=layanan,
                    username=username,
                    password=password,
                    catatan=catatan,
                )
            self.after(0, lambda: self._on_done(new_vault))

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, new_vault):
        save_text = "Tambah" if self._mode == "add" else "Simpan"
        self._save_btn.configure(text=save_text, state="normal")

        if new_vault is None:
            self._status_label.configure(
                text="Gagal menyimpan. Periksa koneksi server.",
                text_color=COLORS["danger"],
            )
            return

        self._parent.refresh_vault(new_vault)
        self.destroy()
