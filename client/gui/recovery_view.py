import customtkinter as ctk
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


class RecoveryView(ctk.CTkFrame):

    def __init__(self, master, recovery_share: dict, **kwargs):
        super().__init__(master, fg_color=COLORS["bg_dark"], **kwargs)
        self.master = master
        self._recovery_share = recovery_share
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

        # Judul
        ctk.CTkLabel(
            container,
            text="Vault Berhasil Dibuat",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["success"],
        ).grid(row=0, column=0, padx=40, pady=(36, 6))

        ctk.CTkLabel(
            container,
            text="Simpan recovery share berikut di tempat yang aman.",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_secondary"],
        ).grid(row=1, column=0, padx=40, pady=(0, 20))

        # Peringatan
        warn_frame = ctk.CTkFrame(
            container,
            fg_color=COLORS["warning_bg"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["warning_border"],
        )
        warn_frame.grid(row=2, column=0, padx=32, pady=(0, 20), sticky="ew")

        ctk.CTkLabel(
            warn_frame,
            text="PERINGATAN: Recovery share ini hanya ditampilkan sekali.\n"
                 "Tanpa recovery share, vault tidak dapat dibuka jika server mati.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["warning_text"],
            wraplength=380,
            justify="center",
        ).pack(padx=16, pady=14)

        # Data recovery share
        share_value = self._recovery_share.get("value", "")
        share_index = self._recovery_share.get("index", "")

        info_frame = ctk.CTkFrame(
            container,
            fg_color=COLORS["bg_input"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        info_frame.grid(row=3, column=0, padx=32, pady=(0, 12), sticky="ew")
        info_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            info_frame,
            text="Index:",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(14, 4), sticky="w")

        ctk.CTkLabel(
            info_frame,
            text=str(share_index),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_primary"],
            anchor="w",
        ).grid(row=0, column=1, padx=8, pady=(14, 4), sticky="w")

        ctk.CTkLabel(
            info_frame,
            text="Value:",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
            anchor="w",
        ).grid(row=1, column=0, padx=16, pady=(4, 14), sticky="w")

        # Textbox untuk nilai share agar bisa di-select dan disalin
        share_textbox = ctk.CTkTextbox(
            info_frame,
            height=60,
            fg_color=COLORS["bg_dark"],
            text_color=COLORS["accent"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6,
            font=ctk.CTkFont(family="Courier", size=11),
            wrap="word",
        )
        share_textbox.grid(row=1, column=1, padx=(8, 16), pady=(4, 14), sticky="ew")
        share_textbox.insert("1.0", share_value)
        share_textbox.configure(state="disabled")

        # Tombol salin
        self._copy_btn = ctk.CTkButton(
            container,
            text="Salin Recovery Share",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_input"],
            hover_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            border_width=1,
            border_color=COLORS["border"],
            height=38,
            corner_radius=8,
            command=lambda: self._copy_to_clipboard(share_value),
        )
        self._copy_btn.grid(row=4, column=0, padx=32, pady=(0, 12), sticky="ew")

        # Tombol lanjut ke vault
        ctk.CTkButton(
            container,
            text="Saya Sudah Menyimpan Recovery Share - Lanjut",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            height=44,
            corner_radius=8,
            command=self.master.goto_vault,
        ).grid(row=5, column=0, padx=32, pady=(0, 32), sticky="ew")

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._copy_btn.configure(text="Tersalin!")
        self.after(2000, lambda: self._copy_btn.configure(text="Salin Recovery Share"))
