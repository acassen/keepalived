#!/usr/bin/env python3
"""Render social card for the keepalived site.

To make a card for another page, copy this file, change OUT, HEAD and SUB, and
set image: in that page front matter. Needs Pillow and the DejaVu Sans fonts.
"""

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.normpath(os.path.join(HERE, "..", "docs"))
LOGO = os.path.join(DOCS, "assets", "keepalived-logo.png")
OUT = os.path.join(DOCS, "images", "vrrp-hmac-card.png")
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

W, H = 1200, 630
WHITE = (255, 255, 255)
ORANGE = (247, 147, 30)
HEAD = (63, 64, 66)
SUB = (122, 123, 125)
HEAD_TEXT = "VRRP HMAC Authentication"
SUB_TEXT = "Integrity and replay protection for VRRP adverts"


def fit_font(draw, path, text, size, maxw):
    """Largest font no wider than maxw, shrinking from size in 2px steps."""
    while size > 10:
        font = ImageFont.truetype(path, size)
        if draw.textlength(text, font=font) <= maxw:
            return font
        size -= 2
    return ImageFont.truetype(path, size)


def main():
    base = Image.new("RGB", (W, H), WHITE)
    draw = ImageDraw.Draw(base)

    # Centered logo in the upper area.
    logo = Image.open(LOGO).convert("RGBA")
    lw = 600
    lh = round(logo.height * lw / logo.width)
    logo = logo.resize((lw, lh), Image.LANCZOS)
    ly = 60
    base.paste(logo, ((W - lw) // 2, ly), logo)

    # Brand orange accent rule under the logo.
    rule_w, rule_h = 120, 6
    ry = ly + lh + 36
    draw.rounded_rectangle(
        [(W - rule_w) // 2, ry, (W + rule_w) // 2, ry + rule_h], radius=3, fill=ORANGE
    )

    maxw = W - 160
    head_font = fit_font(draw, BOLD, HEAD_TEXT, 62, maxw)
    sub_font = fit_font(draw, REG, SUB_TEXT, 36, maxw)
    head_y = ry + rule_h + 60
    draw.text((W / 2, head_y), HEAD_TEXT, font=head_font, fill=HEAD, anchor="mm")
    draw.text((W / 2, head_y + 70), SUB_TEXT, font=sub_font, fill=SUB, anchor="mm")

    base.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} ({W}x{H})")


if __name__ == "__main__":
    main()
