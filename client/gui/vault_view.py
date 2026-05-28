import customtkinter as ctk
import threading
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vault as vault_logic

COLORS = {
    "bg_dark":        "#0f1117",
    "bg_card":        "#1a1d27",
    "bg_input":       "#252836",
    "bg_row":         "#1e2133",
    "bg_row_hover":   "#252840",
    "accent":         "#4f8ef7",
    "accent_hover":   "#3a7de0",
    "danger":         "#e05c5c",
    "danger_hover":   "#c94444",
    "success":        "#4caf7d",
    "text_primary":   "#f0f2f8",
    "text_secondary": "#8a8fa8",
    "border":         "#2e3146",
    "warning_text":   "#f0c040",
}


class VaultView(ctk.CTkFrame):

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS["bg_dark"], **kwargs)
        self.master = master
        self._vault  = list(master.session.get("vault", []))
        self._mode   = master.session.get("mode", "normal")
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", self._on_search)
        self._build_ui()
        self._render_entries()

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_list_area()
        self._build_status_bar()

    def _build_header(self):
        header = ctk.CTkFrame(
            self,
            fg_color=COLORS["bg_card"],
            corner_radius=0,
            border_width=0,
        )
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        # Judul + info pengguna
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, padx=24, pady=16, sticky="w")

        ctk.CTkLabel(
            left,
            text="Password Manager",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(side="left", padx=(0, 12))

        mode_color = COLORS["warning_text"] if self._mode == "backup" else COLORS["success"]
        mode_text  = "BACKUP" if self._mode == "backup" else "NORMAL"
        ctk.CTkLabel(
            left,
            text=mode_text,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=mode_color,
            fg_color=COLORS["bg_input"],
            corner_radius=4,
            width=60,
            height=22,
        ).pack(side="left")

        # Search bar
        search_frame = ctk.CTkFrame(header, fg_color="transparent")
        search_frame.grid(row=0, column=1, padx=16, pady=16)

        self._search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Cari layanan...",
            textvariable=self._search_var,
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_secondary"],
            height=36,
            corner_radius=8,
            width=240,
        )
        self._search_entry.pack()

        # Tombol kanan
        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=2, padx=24, pady=16, sticky="e")

        if self._mode == "normal":
            ctk.CTkButton(
                right,
                text="Tambah Password",
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"],
                height=36,
                corner_radius=8,
                command=self._open_add_dialog,
            ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            right,
            text="Keluar",
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            hover_color=COLORS["bg_input"],
            border_width=1,
            border_color=COLORS["border"],
            height=36,
            corner_radius=8,
            command=self.master.goto_login,
        ).pack(side="left")

    def _build_list_area(self):
        # Frame dengan scrollable list
        list_outer = ctk.CTkFrame(self, fg_color="transparent")
        list_outer.grid(row=1, column=0, sticky="nsew", padx=20, pady=12)
        list_outer.grid_rowconfigure(1, weight=1)
        list_outer.grid_columnconfigure(0, weight=1)

        # Header kolom tabel
        col_header = ctk.CTkFrame(
            list_outer,
            fg_color=COLORS["bg_input"],
            corner_radius=8,
        )
        col_header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        col_header.grid_columnconfigure(0, weight=2)
        col_header.grid_columnconfigure(1, weight=2)
        col_header.grid_columnconfigure(2, weight=2)
        col_header.grid_columnconfigure(3, weight=1)

        for i, text in enumerate(["Layanan", "Username", "Password", "Aksi"]):
            ctk.CTkLabel(
                col_header,
                text=text,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_secondary"],
                anchor="w" if i < 3 else "center",
            ).grid(row=0, column=i, padx=16, pady=8, sticky="ew" if i < 3 else "")

        # Scrollable frame untuk baris data
        self._scroll_frame = ctk.CTkScrollableFrame(
            list_outer,
            fg_color=COLORS["bg_card"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
            scrollbar_button_color=COLORS["border"],
            scrollbar_button_hover_color=COLORS["accent"],
        )
        self._scroll_frame.grid(row=1, column=0, sticky="nsew")
        self._scroll_frame.grid_columnconfigure(0, weight=2)
        self._scroll_frame.grid_columnconfigure(1, weight=2)
        self._scroll_frame.grid_columnconfigure(2, weight=2)
        self._scroll_frame.grid_columnconfigure(3, weight=1)

        # Placeholder saat kosong
        self._empty_label = ctk.CTkLabel(
            self._scroll_frame,
            text="Vault kosong. Klik 'Tambah Password' untuk memulai.",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
        )

    def _build_status_bar(self):
        self._status_bar = ctk.CTkFrame(
            self,
            fg_color=COLORS["bg_card"],
            corner_radius=0,
            height=32,
        )
        self._status_bar.grid(row=2, column=0, sticky="ew")

        self._status_label = ctk.CTkLabel(
            self._status_bar,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        )
        self._status_label.pack(side="left", padx=20)

        username = self.master.session.get("username", "")
        ctk.CTkLabel(
            self._status_bar,
            text=f"Pengguna: {username}",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        ).pack(side="right", padx=20)

    def _render_entries(self, filter_text: str = ""):
        for widget in self._scroll_frame.winfo_children():
            widget.destroy()

        filtered = [
            (i, entry) for i, entry in enumerate(self._vault)
            if filter_text.lower() in entry.get("nama_layanan", "").lower()
            or filter_text.lower() in entry.get("username", "").lower()
        ]

        if not filtered:
            self._empty_label = ctk.CTkLabel(
                self._scroll_frame,
                text=(
                    "Tidak ada hasil untuk pencarian ini."
                    if filter_text
                    else "Vault kosong. Klik 'Tambah Password' untuk memulai."
                ),
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text_secondary"],
            )
            self._empty_label.grid(
                row=0, column=0, columnspan=4, pady=40
            )
            self._update_count(len(filtered))
            return

        for row_idx, (real_idx, entry) in enumerate(filtered):
            self._build_row(row_idx, real_idx, entry)

        self._update_count(len(filtered))

    def _build_row(self, row_idx: int, real_idx: int, entry: dict):
        bg = COLORS["bg_row"] if row_idx % 2 == 0 else COLORS["bg_card"]

        row_frame = ctk.CTkFrame(
            self._scroll_frame,
            fg_color=bg,
            corner_radius=6,
            height=48,
        )
        row_frame.grid(row=row_idx, column=0, columnspan=4, sticky="ew", pady=1)
        row_frame.grid_columnconfigure(0, weight=2)
        row_frame.grid_columnconfigure(1, weight=2)
        row_frame.grid_columnconfigure(2, weight=2)
        row_frame.grid_columnconfigure(3, weight=1)
        row_frame.grid_propagate(False)

        # Nama layanan
        ctk.CTkLabel(
            row_frame,
            text=entry.get("nama_layanan", ""),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_primary"],
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=10, sticky="ew")

        # Username
        ctk.CTkLabel(
            row_frame,
            text=entry.get("username", ""),
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=1, padx=16, pady=10, sticky="ew")

        # Password (tersembunyi)
        pass_var = ctk.StringVar(value="**********")
        pass_label = ctk.CTkLabel(
            row_frame,
            textvariable=pass_var,
            font=ctk.CTkFont(size=13, family="Courier"),
            text_color=COLORS["text_secondary"],
            anchor="w",
        )
        pass_label.grid(row=0, column=2, padx=16, pady=10, sticky="ew")

        # Tombol aksi
        btn_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        btn_frame.grid(row=0, column=3, padx=8, pady=6)

        # Tombol tampilkan/sembunyikan password
        show_btn = ctk.CTkButton(
            btn_frame,
            text="Tampilkan",
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            height=28,
            width=80,
            corner_radius=6,
            command=lambda e=entry, v=pass_var: self._toggle_password(e, v),
        )
        show_btn.pack(side="left", padx=2)

        # Tombol salin
        ctk.CTkButton(
            btn_frame,
            text="Salin",
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            height=28,
            width=48,
            corner_radius=6,
            command=lambda e=entry: self._copy_password(e.get("password", "")),
        ).pack(side="left", padx=2)

        # Tombol edit dan hapus (mode normal saja)
        if self._mode == "normal":
            ctk.CTkButton(
                btn_frame,
                text="Edit",
                font=ctk.CTkFont(size=11),
                fg_color=COLORS["bg_input"],
                hover_color=COLORS["border"],
                text_color=COLORS["accent"],
                height=28,
                width=44,
                corner_radius=6,
                command=lambda idx=real_idx: self._open_edit_dialog(idx),
            ).pack(side="left", padx=2)

            ctk.CTkButton(
                btn_frame,
                text="Hapus",
                font=ctk.CTkFont(size=11),
                fg_color="transparent",
                hover_color=COLORS["danger_hover"],
                text_color=COLORS["danger"],
                height=28,
                width=52,
                corner_radius=6,
                command=lambda idx=real_idx: self._confirm_delete(idx),
            ).pack(side="left", padx=2)


    def _on_search(self, *args):
        self._render_entries(self._search_var.get())

    def _update_count(self, count: int):
        total = len(self._vault)
        if count == total:
            self._status_label.configure(text=f"{total} password tersimpan")
        else:
            self._status_label.configure(text=f"Menampilkan {count} dari {total} password")

    def _toggle_password(self, entry: dict, var: ctk.StringVar):
        current = var.get()
        if current == "**********":
            var.set(entry.get("password", ""))
        else:
            var.set("**********")

    def _copy_password(self, password: str):
        self.clipboard_clear()
        self.clipboard_append(password)
        self._status_label.configure(text="Password disalin ke clipboard.", text_color=COLORS["success"])
        self.after(3000, lambda: self._status_label.configure(
            text=f"{len(self._vault)} password tersimpan",
            text_color=COLORS["text_secondary"],
        ))

    def _open_add_dialog(self):
        from gui.add_edit_view import AddEditDialog
        dialog = AddEditDialog(self, mode="add")
        self.wait_window(dialog)

    def _open_edit_dialog(self, index: int):
        from gui.add_edit_view import AddEditDialog
        dialog = AddEditDialog(self, mode="edit", index=index, entry=self._vault[index])
        self.wait_window(dialog)

    def _confirm_delete(self, index: int):
        entry = self._vault[index]
        dialog = _ConfirmDialog(
            self,
            title="Hapus Password",
            message=f"Hapus password untuk '{entry.get('nama_layanan', '')}'?",
        )
        self.wait_window(dialog)
        if dialog.confirmed:
            self._do_delete(index)

    def _do_delete(self, index: int):
        master_password = self.master.session.get("master_password")
        self._status_label.configure(text="Menghapus...", text_color=COLORS["text_secondary"])

        def worker():
            new_vault = vault_logic.delete_entry(self._vault, master_password, index)
            self.after(0, lambda: self._on_vault_updated(new_vault))

        threading.Thread(target=worker, daemon=True).start()

    def refresh_vault(self, new_vault: list):
        """Dipanggil oleh AddEditDialog setelah perubahan."""
        self._vault = list(new_vault)
        self.master.session["vault"] = self._vault
        self._render_entries(self._search_var.get())

    def _on_vault_updated(self, new_vault):
        if new_vault is None:
            self._status_label.configure(
                text="Gagal menyimpan perubahan.",
                text_color=COLORS["danger"],
            )
        else:
            self.refresh_vault(new_vault)
            self._status_label.configure(
                text="Perubahan disimpan.",
                text_color=COLORS["success"],
            )
            self.after(3000, lambda: self._status_label.configure(
                text=f"{len(self._vault)} password tersimpan",
                text_color=COLORS["text_secondary"],
            ))


class _ConfirmDialog(ctk.CTkToplevel):
    """Dialog konfirmasi sederhana."""

    def __init__(self, parent, title: str, message: str):
        super().__init__(parent)
        self.title(title)
        self.geometry("360x160")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_card"])
        self.grab_set()
        self.confirmed = False
        self._build(message)

    def _build(self, message: str):
        ctk.CTkLabel(
            self,
            text=message,
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_primary"],
            wraplength=300,
            justify="center",
        ).pack(pady=(30, 20))

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack()

        ctk.CTkButton(
            btn_frame,
            text="Batal",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            width=110,
            height=36,
            corner_radius=8,
            command=self.destroy,
        ).pack(side="left", padx=6)

        ctk.CTkButton(
            btn_frame,
            text="Hapus",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["danger"],
            hover_color="#c94444",
            text_color=COLORS["text_primary"],
            width=110,
            height=36,
            corner_radius=8,
            command=self._confirm,
        ).pack(side="left", padx=6)

    def _confirm(self):
        self.confirmed = True
        self.destroy()
