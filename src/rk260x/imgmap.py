#!/usr/bin/env python3
"""rk260x firmware image-map handling.

Canonical format: JSON ("rk260x-image-map/1"), one file per device:

    {
      "format": "rk260x-image-map/1",
      "device": "Explay M3i",
      "firmware": "Firmware M3i 070930.rfw",
      "pixel_format": "BE-BGR565",
      "images": [
        {"name": "VolBar00", "offset": 8933178, "width": 11, "height": 88}
      ]
    }

`offset` is the byte offset within the firmware container file (.rfw).
Extra keys per image (added by analysis tooling) are preserved as-is:
"x"/"y" (screen position), "group" (animation set), "stride", "callsite"
(runtime code address referencing it), "source" ("hand" | "automap"),
"confidence".

"""
import json, os

MAP_FORMAT = "rk260x-image-map/1"

LEGACY_KEYS = ("name", "offset", "width", "height")


def load_map(path):
    """Load a map (JSON canonical, legacy .tl accepted). Returns map dict."""
    m = json.loads(open(path, "r", encoding="utf-8", errors="replace").read())
    if m.get("format") != MAP_FORMAT:
        raise ValueError(f"{path}: unknown map format {m.get('format')!r}")
    return m


def save_map(path, m, device=None, firmware=None):
    out = dict(m)
    out["format"] = MAP_FORMAT
    out.setdefault("pixel_format", "BE-BGR565")
    if device:
        out["device"] = device
    if firmware:
        out["firmware"] = firmware
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")


def rows_of(m):
    """Rows as [name, offset, width, height] lists (GUI table format)."""
    return [[im["name"], im["offset"], im["width"], im["height"]]
            for im in m["images"]]


def map_from_rows(rows, base=None):
    """Build a map dict from GUI-style rows, preserving extra keys of base."""
    base = base or {"format": MAP_FORMAT, "device": None, "firmware": None,
                    "pixel_format": "BE-BGR565", "images": []}
    old = {im["name"]: im for im in base.get("images", [])}
    images = []
    for name, off, w, h in rows:
        im = dict(old.get(name, {}))
        im.update({"name": name, "offset": int(off), "width": int(w),
                   "height": int(h)})
        images.append(im)
    m = dict(base)
    m["images"] = images
    return m


if __name__ == "__main__":
    import sys
    src, dst = sys.argv[1], sys.argv[2]
    save_map(dst, load_map(src))
    print(f"converted {src} -> {dst}")
