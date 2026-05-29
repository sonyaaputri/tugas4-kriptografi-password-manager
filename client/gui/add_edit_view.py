import customtkinter as ctk
import threading
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vault as vault_logic
from crypto.csprng import generate_password

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
    "warning_text":   "#f0c040",
}


class AddEditDialog(ctk.CTkToplevel):
    """
    Dialog untuk menambah atau mengedit entri password.

    Fitur:
    - Input manual username/password
    - Pembangkitan password otomatis dengan CSPRNG
    - Toggle tampilkan/sembunyikan password
    - Pilihan panjang & kategori karakter
    """

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
        self._show_pw = False

        title = "Tambah Password" if mode == "add" else "Edit Password"
        self.title(title)
        self.geometry("460x500")
        self.minsize(420, 420)
        self.resizable(True, True)
        self.configure(fg_color=COLORS["bg_dark"])
        self.grab_set()

        self._build_ui(title)

    def _build_ui(self, title: str):
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # ── Scrollable area (semua field di sini) ────────────
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS["bg_card"],
            scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["accent"],
            corner_radius=0,
        )
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        # Judul
        ctk.CTkLabel(
            scroll,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, padx=24, pady=(20, 16), sticky="w")

        ctk.CTkLabel(
            scroll, text="Nama Layanan / Website",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=24, pady=(0, 2))

        self._layanan_entry = ctk.CTkEntry(
            scroll,
            placeholder_text="Contoh: Google, GitHub",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._layanan_entry.grid(row=2, column=0, sticky="ew", padx=24)
        if self._entry.get("nama_layanan"):
            self._layanan_entry.insert(0, self._entry["nama_layanan"])

        ctk.CTkLabel(
            scroll, text="Username / Email",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=3, column=0, sticky="w", padx=24, pady=(12, 2))

        self._username_entry = ctk.CTkEntry(
            scroll,
            placeholder_text="Contoh: user@email.com",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._username_entry.grid(row=4, column=0, sticky="ew", padx=24)
        if self._entry.get("username"):
            self._username_entry.insert(0, self._entry["username"])

        pw_header = ctk.CTkFrame(scroll, fg_color="transparent")
        pw_header.grid(row=5, column=0, sticky="ew", padx=24, pady=(12, 2))
        pw_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            pw_header, text="Password",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Tombol toggle tampilkan/sembunyikan
        self._toggle_btn = ctk.CTkButton(
            pw_header,
            text="Tampilkan",
            font=ctk.CTkFont(size=11),
            fg_color="transparent",
            text_color=COLORS["accent"],
            hover_color=COLORS["bg_input"],
            height=22,
            width=80,
            corner_radius=4,
            command=self._toggle_password_visibility,
        )
        self._toggle_btn.grid(row=0, column=1, sticky="e")

        self._password_entry = ctk.CTkEntry(
            scroll,
            placeholder_text="Password untuk layanan ini",
            show="*",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._password_entry.grid(row=6, column=0, sticky="ew", padx=24)
        if self._entry.get("password"):
            self._password_entry.insert(0, self._entry["password"])

        gen_frame = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["bg_input"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        gen_frame.grid(row=7, column=0, sticky="ew", padx=24, pady=(8, 0))
        gen_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            gen_frame,
            text="⚡ Generate Otomatis (CSPRNG)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["warning_text"],
            anchor="w",
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(8, 4))

        # Panjang password
        ctk.CTkLabel(
            gen_frame, text="Panjang:",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_secondary"],
        ).grid(row=1, column=0, padx=(12, 4), pady=4)

        self._length_var = ctk.StringVar(value="16")
        ctk.CTkEntry(
            gen_frame,
            textvariable=self._length_var,
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            height=30,
            width=55,
            corner_radius=6,
        ).grid(row=1, column=1, padx=4, pady=4, sticky="w")

        # Tombol generate
        ctk.CTkButton(
            gen_frame,
            text="Generate",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=30,
            width=80,
            corner_radius=6,
            command=self._generate_password,
        ).grid(row=1, column=2, padx=(4, 12), pady=4)

        # Checkbox kategori karakter
        self._use_upper  = ctk.BooleanVar(value=True)
        self._use_lower  = ctk.BooleanVar(value=True)
        self._use_digits = ctk.BooleanVar(value=True)
        self._use_sym    = ctk.BooleanVar(value=True)

        chk_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
        chk_frame.grid(row=2, column=0, columnspan=3, padx=8, pady=(0, 8), sticky="w")

        for var, label in [
            (self._use_upper,  "A-Z"),
            (self._use_lower,  "a-z"),
            (self._use_digits, "0-9"),
            (self._use_sym,    "!@#"),
        ]:
            ctk.CTkCheckBox(
                chk_frame, text=label, variable=var,
                font=ctk.CTkFont(size=11),
                text_color=COLORS["text_secondary"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"],
                border_color=COLORS["border"],
                width=16, height=16, corner_radius=4,
            ).pack(side="left", padx=6)

        ctk.CTkLabel(
            scroll, text="Catatan (opsional)",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=8, column=0, sticky="w", padx=24, pady=(12, 2))

        self._catatan_entry = ctk.CTkEntry(
            scroll,
            placeholder_text="Catatan tambahan",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=40,
            corner_radius=8,
        )
        self._catatan_entry.grid(row=9, column=0, sticky="ew", padx=24)
        if self._entry.get("catatan"):
            self._catatan_entry.insert(0, self._entry["catatan"])

        self._status_label = ctk.CTkLabel(
            scroll, text="",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["danger"],
            wraplength=380,
        )
        self._status_label.grid(row=10, column=0, padx=24, pady=(8, 4))

        btn_bar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=0)
        btn_bar.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        btn_bar.grid_columnconfigure(0, weight=1)
        btn_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_bar,
            text="Batal",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            height=44,
            corner_radius=0,
            command=self.destroy,
        ).grid(row=0, column=0, sticky="ew")

        save_text = "Tambah" if self._mode == "add" else "Simpan"
        self._save_btn = ctk.CTkButton(
            btn_bar,
            text=save_text,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["text_primary"],
            height=44,
            corner_radius=0,
            command=self._do_save,
        )
        self._save_btn.grid(row=0, column=1, sticky="ew")

    def _toggle_password_visibility(self):
        self._show_pw = not self._show_pw
        if self._show_pw:
            self._password_entry.configure(show="")
            self._toggle_btn.configure(text="Sembunyikan")
        else:
            self._password_entry.configure(show="*")
            self._toggle_btn.configure(text="Tampilkan")

    def _generate_password(self):
        try:
            length = int(self._length_var.get().strip())
            if not (4 <= length <= 128):
                self._set_status("Panjang password harus antara 4 dan 128.")
                return
        except ValueError:
            self._set_status("Panjang password harus berupa angka.")
            return

        if not any([self._use_upper.get(), self._use_lower.get(),
                    self._use_digits.get(), self._use_sym.get()]):
            self._set_status("Pilih minimal satu kategori karakter.")
            return

        try:
            password = generate_password(
                length,
                use_uppercase=self._use_upper.get(),
                use_lowercase=self._use_lower.get(),
                use_digits=self._use_digits.get(),
                use_symbols=self._use_sym.get(),
            )
        except ValueError as e:
            self._set_status(str(e))
            return

        # Isi ke field password dan tampilkan
        self._password_entry.delete(0, "end")
        self._password_entry.insert(0, password)
        if not self._show_pw:
            self._password_entry.configure(show="")
            self._toggle_btn.configure(text="Sembunyikan")
            self._show_pw = True

        self._set_status(f"Password {length} karakter berhasil dibangkitkan!", is_error=False)

    def _set_status(self, text: str, is_error: bool = True):
        color = COLORS["danger"] if is_error else COLORS["success"]
        self._status_label.configure(text=text, text_color=color)

    def _do_save(self):
        layanan  = self._layanan_entry.get().strip()
        username = self._username_entry.get().strip()
        password = self._password_entry.get()
        catatan  = self._catatan_entry.get().strip()

        if not layanan:
            self._set_status("Nama layanan tidak boleh kosong.")
            return
        if not username:
            self._set_status("Username tidak boleh kosong.")
            return
        if not password:
            self._set_status("Password tidak boleh kosong.")
            return

        self._save_btn.configure(text="Menyimpan...", state="disabled")
        self._set_status("")

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
            self._set_status("Gagal menyimpan. Periksa koneksi server.")
            return

        self._parent.refresh_vault(new_vault)
        self.destroy()
