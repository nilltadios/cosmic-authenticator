# Writes small, smoothed QR codes of a fake otpauth:// link, the way a
# screenshot of a web page shows them: version 9 (53 modules) drawn at
# 200-215 px, so a module is about 4 px and not a whole number of pixels,
# on a light card. rqrr 0.11 alone misses many of them (all at 200 and
# 215 px on 2026-11-11); the app's reader must read every one.
#
#   uv run --no-project --with "qrcode[pil]" demo/make-small-qr.py
#       writes demo/small-qr.png (used by the import tests)
#   uv run --no-project --with "qrcode[pil]" demo/make-small-qr.py --sweep DIR
#       writes 48 variants (4 error-correction levels x 3 sizes x 4 filters)
#       into DIR, for demo/qr-sweep.sh
import sys
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q

LINK = "otpauth://totp/Example:someone.name%40example.com?secret=KZMGSZKWMNTTAZSJPI4DOWLCPJJGGNCR&issuer=Example"
LEVELS = {"L": ERROR_CORRECT_L, "M": ERROR_CORRECT_M, "Q": ERROR_CORRECT_Q, "H": ERROR_CORRECT_H}
FILTERS = {"lanczos": Image.LANCZOS, "bilinear": Image.BILINEAR, "box": Image.BOX, "bicubic": Image.BICUBIC}


def card(level: str, size: int, resample: int) -> Image.Image:
    qr = qrcode.QRCode(version=9, error_correction=LEVELS[level], border=0, box_size=10)
    qr.add_data(LINK)
    qr.make(fit=False)
    code = qr.make_image().convert("L").resize((size, size), resample)
    out = Image.new("RGB", (size + 62, size + 51), (225, 240, 240))
    ImageDraw.Draw(out).rectangle((23, 17, size + 39, size + 33), fill=(255, 255, 255))
    out.paste(code, (31, 25))
    return out


if len(sys.argv) == 3 and sys.argv[1] == "--sweep":
    folder = Path(sys.argv[2])
    folder.mkdir(parents=True, exist_ok=True)
    for level in LEVELS:
        for size in (200, 208, 215):
            for name, resample in FILTERS.items():
                card(level, size, resample).save(folder / f"{level}-{size}-{name}.png")
    print(f"Wrote 48 images to {folder}")
else:
    out = Path(__file__).with_name("small-qr.png")
    card("M", 215, Image.LANCZOS).save(out)
    print(f"Wrote {out}")
