"""Генерирует иконку и картинки мастера установки из icons/ (запускать вручную при смене логотипа).

  python installer/tools/make_brand.py

Создаёт:
  installer/assets/legion.ico            — иконка установщика и программы
  installer/assets/wizard-large.bmp      — боковая картинка мастера (164x314)
  installer/assets/wizard-small.bmp      — маленькая картинка мастера (55x58)
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "installer" / "assets"
LOGO = ROOT / "icons" / "logo-mark.png"
ICON128 = ROOT / "icons" / "icon128.png"

BG_TOP = (22, 26, 34)
BG_BOTTOM = (10, 12, 16)
ACCENT = (62, 207, 142)


def _mark(size: int) -> Image.Image:
    """Белый знак на прозрачном фоне, вписанный в квадрат size."""
    src = Image.open(LOGO).convert("RGBA")
    bbox = src.getbbox()
    if bbox:
        src = src.crop(bbox)
    inner = int(size * 0.72)
    src.thumbnail((inner, inner), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.alpha_composite(src, ((size - src.width) // 2, (size - src.height) // 2))
    return canvas


def _rounded_square(size: int, radius: int) -> Image.Image:
    """Тёмный скруглённый квадрат с лёгким градиентом (как в icon128)."""
    base = Image.new("RGBA", (size, size), BG_BOTTOM + (255,))
    grad = ImageDraw.Draw(base)
    for y in range(size):
        t = y / max(1, size - 1)
        color = tuple(int(BG_TOP[i] * (1 - t) + BG_BOTTOM[i] * t) for i in range(3)) + (255,)
        grad.line([(0, y), (size, y)], fill=color)
    mask = Image.new("L", (size * 4, size * 4), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size * 4 - 1, size * 4 - 1), radius=radius * 4, fill=255)
    mask = mask.resize((size, size), Image.LANCZOS)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(base, (0, 0), mask)
    return out


def make_icon() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = []
    for s in sizes:
        tile = _rounded_square(s, max(2, round(s * 0.22)))
        mark = _mark(s)
        tile.alpha_composite(mark)
        frames.append(tile)
    frames[-1].save(
        ASSETS / "legion.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=frames[:-1],
    )


def make_wizard_large() -> None:
    w, h = 164, 314
    img = Image.new("RGB", (w, h), BG_BOTTOM)
    draw = ImageDraw.Draw(img)
    for y in range(h):
        t = y / (h - 1)
        color = tuple(int(BG_TOP[i] * (1 - t) + BG_BOTTOM[i] * t) for i in range(3))
        draw.line([(0, y), (w, y)], fill=color)
    mark = _mark(112)
    img.paste(mark, ((w - 112) // 2, 52), mark)
    draw.rectangle((w // 2 - 22, 190, w // 2 + 22, 192), fill=ACCENT)
    img.save(ASSETS / "wizard-large.bmp", format="BMP")


def make_wizard_small() -> None:
    w, h = 55, 58
    img = Image.new("RGB", (w, h), BG_BOTTOM)
    tile = _rounded_square(44, 10)
    tile.alpha_composite(_mark(44))
    img.paste(tile, ((w - 44) // 2, (h - 44) // 2), tile)
    img.save(ASSETS / "wizard-small.bmp", format="BMP")


if __name__ == "__main__":
    ASSETS.mkdir(parents=True, exist_ok=True)
    make_icon()
    make_wizard_large()
    make_wizard_small()
    print("OK:", ", ".join(p.name for p in sorted(ASSETS.iterdir())))
