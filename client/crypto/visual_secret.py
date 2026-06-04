# Visual Secret Sharing (VSS) untuk Recovery Share (BONUS)
#
# Implementasi skema VSS (2,2) untuk membagi QR code recovery
# share menjadi dua gambar share. Kedua share harus ditumpuk
# (overlay) untuk mengungkap QR code asli.
#
# Konsep Visual Secret Sharing (Naor & Shamir, 1994):
#   - Setiap pixel QR code (hitam/putih) diperluas menjadi blok 2×2
#   - Pixel PUTIH: share1 dan share2 memiliki pola yang SAMA
#     → overlay menghasilkan blok abu-abu (50% hitam)
#   - Pixel HITAM: share1 dan share2 memiliki pola yang KOMPLEMEN
#     → overlay menghasilkan blok HITAM PENUH
#
# Representasi visual:
#   Pixel asli PUTIH (0): share A = [B,W,W,B], share B = [B,W,W,B]
#                          overlay = [B,W,W,B] → abu-abu
#   Pixel asli HITAM (1): share A = [B,W,W,B], share B = [W,B,B,W]
#                          overlay = [B,B,B,B] → hitam penuh
#
# Cara membuat share:
#   1. Konversi recovery share ke QR code (qrcode library)
#   2. Untuk tiap pixel QR, pilih pola acak dari pasangan pola VSS
#   3. Share 1 = pola terpilih, Share 2 = pola sama (putih) / komplemen (hitam)
#
# Cara rekonstruksi:
#   - Tumpuk (OR / multiply) kedua gambar share
#   - Area hitam menjadi lebih gelap → QR code terungkap
#
# Library: qrcode, Pillow (PIL)

import secrets
import io
from typing import Tuple

try:
    import qrcode
    from PIL import Image
    _VSS_AVAILABLE = True
except ImportError:
    _VSS_AVAILABLE = False


# Pola Blok 2×2 untuk VSS
# Setiap pola adalah tuple 4 bool: (TL, TR, BL, BR)
# True = hitam, False = putih

# Pola untuk pixel HITAM: 2 pola komplemen
_BLACK_PATTERNS = [
    # Pola A          Pola B (komplemen)
    ((True, False, False, True),  (False, True, True, False)),   # diagonal \
    ((False, True, True, False),  (True, False, False, True)),   # diagonal /
    ((True, True, False, False),  (False, False, True, True)),   # vertikal kiri
    ((False, False, True, True),  (True, True, False, False)),   # vertikal kanan
    ((True, False, True, False),  (False, True, False, True)),   # checkerboard 1
    ((False, True, False, True),  (True, False, True, False)),   # checkerboard 2
]

# Pola untuk pixel PUTIH: 2 pola identik (menghasilkan abu-abu saat overlay)
_WHITE_PATTERNS = [
    ((True, False, False, True),  (True, False, False, True)),
    ((False, True, True, False),  (False, True, True, False)),
    ((True, True, False, False),  (True, True, False, False)),
    ((False, False, True, True),  (False, False, True, True)),
    ((True, False, True, False),  (True, False, True, False)),
    ((False, True, False, True),  (False, True, False, True)),
]

# Ukuran blok tiap pixel QR dalam gambar share (2×2 subpixel)
_BLOCK_SIZE = 2

# Ukuran tampil share dan QR akhir agar hasil gabungan tetap mudah dipindai.
_QR_DISPLAY_SCALE = 8
_SHARE_DISPLAY_SCALE = 4
_RECONSTRUCTION_BLOCK_SIZE = _BLOCK_SIZE * _SHARE_DISPLAY_SCALE


def _resize_nearest(image: "Image.Image", scale: int) -> "Image.Image":
    """Resize image with nearest-neighbor scaling."""
    if scale <= 1:
        return image.copy()
    return image.resize(
        (image.width * scale, image.height * scale),
        Image.NEAREST,
    )


def _threshold_overlay_to_qr(combined: "Image.Image") -> "Image.Image":
    """Collapse the VSS overlay back to a clean QR module grid."""
    block_size = None
    for candidate in (_RECONSTRUCTION_BLOCK_SIZE, _BLOCK_SIZE):
        if combined.width % candidate == 0 and combined.height % candidate == 0:
            block_size = candidate
            break

    if block_size is None:
        raise ValueError(
            f"Ukuran share tidak cocok untuk rekonstruksi: {combined.size}"
        )

    qr_width = combined.width // block_size
    qr_height = combined.height // block_size
    qr_modules = Image.new("1", (qr_width, qr_height), color=1)
    src_px = combined.load()
    dst_px = qr_modules.load()
    black_threshold = (block_size * block_size) // 2

    for y in range(qr_height):
        for x in range(qr_width):
            black_pixels = 0
            x0 = x * block_size
            y0 = y * block_size
            for yy in range(y0, y0 + block_size):
                for xx in range(x0, x0 + block_size):
                    if src_px[xx, yy] == 0:
                        black_pixels += 1
            dst_px[x, y] = 0 if black_pixels > black_threshold else 1

    return _resize_nearest(qr_modules, _QR_DISPLAY_SCALE)


# Pembuatan QR Code

def recovery_share_to_qr(recovery_share_str: str) -> "Image.Image":
    """
    Mengkonversi string recovery share menjadi QR code image.

    Parameters
    ----------
    recovery_share_str : string recovery share
                         format: "SSS:{index}:{value_hex}"

    Returns
    -------
    PIL.Image.Image : QR code dalam mode "1" (1-bit pixels, hitam/putih)

    Raises
    ------
    RuntimeError : jika library qrcode/Pillow tidak terinstall
    """
    if not _VSS_AVAILABLE:
        raise RuntimeError(
            "Library qrcode dan Pillow diperlukan untuk fitur Visual Secret Sharing.\n"
            "Jalankan: pip install qrcode[pil] Pillow"
        )

    qr = qrcode.QRCode(
        version         = None,   # auto-detect ukuran terkecil yang cukup
        error_correction= qrcode.constants.ERROR_CORRECT_H,  # 30% recovery
        box_size        = 1,      # 1 pixel per modul QR
        border          = 4,      # 4 modul border putih (standar QR)
    )
    qr.add_data(recovery_share_str)
    qr.make(fit=True)

    # Buat image hitam-putih (mode "1")
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image = qr_image.convert("1")  # pastikan mode 1-bit

    return qr_image


# Pembagian QR Code menjadi 2 Share

def split_qr_to_shares(
    qr_image: "Image.Image"
) -> Tuple["Image.Image", "Image.Image"]:
    """
    Membagi QR code image menjadi dua gambar share VSS (2,2).

    Setiap pixel QR diperluas menjadi blok 2×2 subpixel.
    Ukuran gambar share = 2x ukuran QR asli (karena blok 2×2).

    Properti keamanan:
    - Share 1 saja: tampak noise random, tidak ada informasi QR
    - Share 2 saja: tampak noise random, tidak ada informasi QR
    - Share 1 + Share 2 (overlay): QR code muncul kembali

    Parameters
    ----------
    qr_image : PIL.Image mode "1" (QR code hitam-putih)

    Returns
    -------
    (share1_image, share2_image)
    Kedua gambar berukuran 2x ukuran qr_image, mode "1"

    Raises
    ------
    RuntimeError : jika Pillow tidak terinstall
    """
    if not _VSS_AVAILABLE:
        raise RuntimeError("Library Pillow diperlukan untuk fitur VSS.")

    width, height = qr_image.size

    # Ukuran gambar share: 2x ukuran asli karena blok 2×2
    share_width  = width  * _BLOCK_SIZE
    share_height = height * _BLOCK_SIZE

    # Buat dua gambar share kosong (mode "1", latar putih)
    share1 = Image.new("1", (share_width, share_height), color=1)
    share2 = Image.new("1", (share_width, share_height), color=1)

    # Akses pixel QR code
    qr_pixels = qr_image.load()
    s1_pixels = share1.load()
    s2_pixels = share2.load()

    for y in range(height):
        for x in range(width):
            # Dapatkan nilai pixel QR: 0 = hitam, 255 = putih (mode "1")
            pixel_val = qr_pixels[x, y]
            is_black  = (pixel_val == 0)  # True jika pixel hitam

            # Pilih pasangan pola secara random
            if is_black:
                # Pixel hitam: ambil pasangan pola komplemen secara acak
                pattern_idx = secrets.randbelow(len(_BLACK_PATTERNS))
                pattern1, pattern2 = _BLACK_PATTERNS[pattern_idx]
            else:
                # Pixel putih: ambil pasangan pola identik secara acak
                pattern_idx = secrets.randbelow(len(_WHITE_PATTERNS))
                pattern1, pattern2 = _WHITE_PATTERNS[pattern_idx]

            # Terapkan pola ke blok 2×2 di kedua share
            # Koordinat blok di gambar share
            bx = x * _BLOCK_SIZE
            by = y * _BLOCK_SIZE

            # TL=top-left, TR=top-right, BL=bottom-left, BR=bottom-right
            tl, tr, bl, br = pattern1
            s1_pixels[bx,   by  ] = 0 if tl else 1  # mode "1": 0=hitam, 1=putih
            s1_pixels[bx+1, by  ] = 0 if tr else 1
            s1_pixels[bx,   by+1] = 0 if bl else 1
            s1_pixels[bx+1, by+1] = 0 if br else 1

            tl, tr, bl, br = pattern2
            s2_pixels[bx,   by  ] = 0 if tl else 1
            s2_pixels[bx+1, by  ] = 0 if tr else 1
            s2_pixels[bx,   by+1] = 0 if bl else 1
            s2_pixels[bx+1, by+1] = 0 if br else 1

    return share1, share2


# Rekonstruksi QR Code dari 2 Share

def combine_shares(
    share1: "Image.Image",
    share2: "Image.Image"
) -> "Image.Image":
    """
    Menggabungkan dua share VSS dan mengembalikan QR code yang bersih.

    Hasil akhir bukan overlay grayscale mentah, tetapi QR module grid yang
    sudah dipulihkan lalu diperbesar lagi agar mudah dipindai.

    Parameters
    ----------
    share1 : PIL.Image mode "1"
    share2 : PIL.Image mode "1"

    Returns
    -------
    PIL.Image.Image : QR code hasil rekonstruksi (mode "1" binary)

    Raises
    ------
    ValueError  : jika ukuran kedua share berbeda
    RuntimeError: jika Pillow tidak terinstall
    """
    if not _VSS_AVAILABLE:
        raise RuntimeError("Library Pillow diperlukan untuk fitur VSS.")

    if share1.size != share2.size:
        raise ValueError(
            f"Ukuran share berbeda: {share1.size} vs {share2.size}"
        )

    # Konversi ke binary untuk operasi pixel
    s1 = share1.convert("1")
    s2 = share2.convert("1")

    # Overlay: pixel hitam muncul jika salah satu share hitam di posisi itu.
    combined = Image.new("1", share1.size, color=1)
    s1_px = s1.load()
    s2_px = s2.load()
    c_px  = combined.load()

    width, height = share1.size
    for y in range(height):
        for x in range(width):
            if s1_px[x, y] == 0 or s2_px[x, y] == 0:
                c_px[x, y] = 0
            else:
                c_px[x, y] = 1

    return _threshold_overlay_to_qr(combined)


# API Publik

def create_visual_shares(
    recovery_share_str: str,
    output_dir: str = "."
) -> Tuple[str, str, str]:
    """
    Pipeline lengkap: recovery share string → 2 gambar share VSS.

    1. Buat QR code dari recovery share string
    2. Bagi QR code menjadi 2 share VSS
    3. Simpan ketiga gambar (QR asli, share1, share2) ke output_dir

    Parameters
    ----------
    recovery_share_str : string recovery share "SSS:{index}:{hex}"
    output_dir         : direktori untuk menyimpan gambar output

    Returns
    -------
    (qr_path, share1_path, share2_path)
    Path ke file gambar yang dihasilkan.

    Raises
    ------
    RuntimeError : jika library tidak terinstall
    """
    if not _VSS_AVAILABLE:
        raise RuntimeError(
            "Library qrcode dan Pillow diperlukan.\n"
            "Jalankan: pip install qrcode[pil] Pillow"
        )

    import os

    # 1. Buat QR code
    qr_image = recovery_share_to_qr(recovery_share_str)
    # Scale up QR untuk visibilitas (tiap modul = 8 pixel)
    qr_display = _resize_nearest(qr_image, _QR_DISPLAY_SCALE)

    # 2. Bagi menjadi 2 share
    share1, share2 = split_qr_to_shares(qr_image)
    # Scale up share untuk visibilitas
    share1_display = _resize_nearest(share1, _SHARE_DISPLAY_SCALE)
    share2_display = _resize_nearest(share2, _SHARE_DISPLAY_SCALE)

    # 3. Simpan gambar
    os.makedirs(output_dir, exist_ok=True)
    qr_path     = os.path.join(output_dir, "recovery_qr.png")
    share1_path = os.path.join(output_dir, "visual_share1.png")
    share2_path = os.path.join(output_dir, "visual_share2.png")

    qr_display.save(qr_path)
    share1_display.save(share1_path)
    share2_display.save(share2_path)

    print(f"[VSS] QR code disimpan     : {qr_path}")
    print(f"[VSS] Visual share 1       : {share1_path}")
    print(f"[VSS] Visual share 2       : {share2_path}")

    return qr_path, share1_path, share2_path


def reconstruct_and_verify(
    share1_path: str,
    share2_path: str,
    output_path: str = "reconstructed_qr.png"
) -> str:
    """
    Rekonstruksi QR code dari dua file share dan simpan hasilnya.

    Parameters
    ----------
    share1_path : path ke gambar share 1
    share2_path : path ke gambar share 2
    output_path : path output hasil rekonstruksi

    Returns
    -------
    str : path ke gambar QR code hasil rekonstruksi yang sudah scanable
    """
    if not _VSS_AVAILABLE:
        raise RuntimeError("Library Pillow diperlukan.")

    share1 = Image.open(share1_path).convert("1")
    share2 = Image.open(share2_path).convert("1")

    combined = combine_shares(share1, share2)
    combined.save(output_path)

    print(f"[VSS] QR code rekonstruksi disimpan: {output_path}")
    return output_path
