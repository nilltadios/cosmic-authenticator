# Writes demo/demo-qr.png, a QR code of a fake otpauth:// link, used by the
# import tests. Run: uv run --no-project --with "qrcode[pil]" demo/make-demo-qr.py
from pathlib import Path

import qrcode

LINK = "otpauth://totp/Demo:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo"
out = Path(__file__).with_name("demo-qr.png")
qrcode.make(LINK, border=4, box_size=8).save(out)
print(f"Wrote {out}")
