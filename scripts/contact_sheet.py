#!/usr/bin/env python3
"""contact_sheet.py — render an operator contact sheet from an image map.

Reads a rk260x-image-map/1 JSON + the .rfw it belongs to, decodes every
mapped BE-BGR565 raster and lays them out on a chessboard grid with:

  * Excel-style cell labels: columns are LETTERS, rows are NUMBERS (A1..)
  * big label in the cell corner + caption strip per image:
      file offset (hex) / width x height / source mark / call-site count
  * label_index.txt next to the sheet mapping labels -> full entries

Usage:
  uv run python scripts/contact_sheet.py MAP.json FIRMWARE.rfw -o OUTDIR
      [--cols 8] [--cell 170x160] [--max-upscale 4]
"""
import argparse
import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'src'))
from rk260x.gui.viewer import FWImage  # noqa: E402

SRC_MARK = {'hand': 'H', 'progression': 'P', 'automap': 'A',
            'hand+automap': 'H+A', 'code': 'C', 'split': 'S',
            'dataflow': 'D', 'linear-fallback': 'L'}


def col_name(n):
    s = ''
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def load_font(size):
    for path in ('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
                 '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'):
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def fit_thumb(img, max_w, max_h, max_upscale=4):
    """Aspect-preserved fit; tiny images upscale (nearest) but stay visible."""
    w, h = img.size
    scale = min(max_w / w, max_h / h, max_upscale)
    scale = max(scale, 1.0) if w * scale < 6 or h * scale < 6 else scale
    if scale >= 1.0:
        scale = min(scale, max_upscale) if w < max_w or h < max_h else 1.0
    tw, th = max(1, round(w * scale)), max(1, round(h * scale))
    return img.resize((tw, th), Image.NEAREST if scale > 1 else Image.BILINEAR)


def render(map_path, fw_path, outdir, cols=8, cell=(170, 160),
           max_upscale=4):
    m = json.load(open(map_path))
    fw = open(fw_path, 'rb').read()
    images = sorted(m['images'], key=lambda i: i['offset'])
    rows = (len(images) + cols - 1) // cols
    cw, ch = cell
    W, H = cols * cw + 1, rows * ch + 60
    sheet = Image.new('RGB', (W, H), 'white')
    d = ImageDraw.Draw(sheet)
    f_big = load_font(22)
    f_cap = load_font(11)
    f_title = load_font(18)

    title = (f"{os.path.basename(map_path)} — {len(images)} images, "
             f"cols={cols}, sources: " +
             '/'.join(f'{v}={k}' for k, v in SRC_MARK.items()
                      if any(i.get('source', '').startswith(k)
                             for i in images)))
    d.text((8, 6), title[:200], font=f_title, fill='black')

    index_lines = []
    for n, im in enumerate(images):
        r, c = divmod(n, cols)
        label = f'{col_name(c + 1)}{r + 1}'
        x0, y0 = c * cw, r * ch + 55
        bg = (240, 240, 240) if (r + c) % 2 == 0 else (208, 208, 208)
        d.rectangle([x0, y0, x0 + cw - 1, y0 + ch - 1], fill=bg,
                    outline=(120, 120, 120))
        w, h, off = im['width'], im['height'], im['offset']
        # raster
        end = off + w * h * 2
        if 0 <= off and end <= len(fw):
            img = FWImage.decode(fw[off:end], w, h)
            th = fit_thumb(img, cw - 16, ch - 42, max_upscale)
            sheet.paste(th, (x0 + (cw - th.width) // 2,
                             y0 + 4 + (ch - 40 - th.height) // 2))
        else:
            d.text((x0 + 12, y0 + 20), 'OUT OF', font=f_cap, fill=(180, 0, 0))
            d.text((x0 + 12, y0 + 32), 'BOUNDS', font=f_cap, fill=(180, 0, 0))
        # big cell label
        d.rectangle([x0 + 2, y0 + 2, x0 + 13 * len(label) + 8, y0 + 24],
                    fill=(255, 255, 160), outline=(90, 90, 90))
        d.text((x0 + 5, y0 + 3), label, font=f_big, fill='black')
        # caption strip
        mark = SRC_MARK.get(im.get('source', '?'), '?')
        cap1 = f'0x{off:x} {w}x{h} {mark}'
        cap2 = im.get('name', '')
        if im.get('callsites'):
            cap1 += f' n={im["callsites"]}'
        d.text((x0 + 5, y0 + ch - 28), cap1, font=f_cap, fill='black')
        d.text((x0 + 5, y0 + ch - 14), cap2[:26], font=f_cap,
               fill=(60, 60, 60))
        index_lines.append(
            f'{label}\t{im.get("name", "?")}\toff=0x{off:x}\t{w}x{h}'
            f'\tsrc={im.get("source", "?")}'
            + (f'\tn={im["callsites"]}' if im.get('callsites') else ''))

    os.makedirs(outdir, exist_ok=True)
    sheet_path = os.path.join(outdir, 'contact_sheet.png')
    sheet.save(sheet_path)
    idx_path = os.path.join(outdir, 'label_index.txt')
    with open(idx_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(index_lines) + '\n')
    print(f'{sheet_path}: {len(images)} images, {rows} rows x {cols} cols')
    print(f'{idx_path}: {len(index_lines)} labels')
    return sheet_path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('map')
    ap.add_argument('firmware')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--cols', type=int, default=8)
    ap.add_argument('--cell', default='170x160',
                    help='cell size WxH (default 170x160)')
    ap.add_argument('--max-upscale', type=int, default=4)
    a = ap.parse_args()
    cw, ch = (int(x) for x in a.cell.lower().split('x'))
    render(a.map, a.firmware, a.outdir, a.cols, (cw, ch), a.max_upscale)


if __name__ == '__main__':
    main()
