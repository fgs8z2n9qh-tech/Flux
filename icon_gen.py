"""Generate icon concepts for VRAMeter and a multi-size .ico from the chosen one.

Usage:
    python icon_gen.py concepts      # render concept_*.png at 256px to preview
    python icon_gen.py build N       # build VRAMeter.ico from concept N (1..4)
"""
import math
import sys

from PIL import Image, ImageDraw

SS = 4  # supersample factor for smooth edges

# palette
BG_TOP = (22, 27, 39)
BG_BOT = (10, 13, 21)
TRACK = (35, 40, 56)
GREEN = (52, 211, 153)
AMBER = (251, 191, 36)
RED = (248, 113, 113)
LIGHT = (230, 233, 240)
MUTED = (138, 144, 162)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def grad3(t):
    """green -> amber -> red across t in [0,1]."""
    if t < 0.5:
        return lerp(GREEN, AMBER, t / 0.5)
    return lerp(AMBER, RED, (t - 0.5) / 0.5)


def base(size):
    """Rounded-square background with a vertical gradient."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    grad = Image.new("RGBA", (size, size))
    gd = grad.load()
    for y in range(size):
        col = lerp(BG_TOP, BG_BOT, y / size)
        for x in range(size):
            gd[x, y] = col + (255,)
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, size - 1, size - 1],
                         radius=int(size * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)
    return img


def concept_ring(size, frac=0.78):
    """A 270-degree arc gauge filled to `frac`, green->amber->red."""
    img = base(size)
    d = ImageDraw.Draw(img)
    pad = size * 0.20
    box = [pad, pad, size - pad, size - pad]
    width = int(size * 0.11)
    start, sweep = 135, 270
    # track
    d.arc(box, start, start + sweep, fill=TRACK, width=width)
    # filled gradient (many small segments)
    steps = 180
    filled = int(steps * frac)
    for i in range(filled):
        a0 = start + sweep * i / steps
        a1 = start + sweep * (i + 1) / steps + 1
        d.arc(box, a0, a1, fill=grad3(i / steps), width=width)
    # inner chip glyph
    cs = size * 0.16
    cx = cy = size / 2
    d.rounded_rectangle([cx - cs, cy - cs, cx + cs, cy + cs],
                        radius=int(size * 0.04), fill=LIGHT)
    d.rounded_rectangle([cx - cs * 0.45, cy - cs * 0.45,
                         cx + cs * 0.45, cy + cs * 0.45],
                        radius=int(size * 0.02), fill=BG_BOT)
    # pins
    pin = size * 0.012
    for k in range(-1, 2):
        off = k * cs * 0.55
        d.rectangle([cx + off - pin, cy - cs - size * 0.05,
                     cx + off + pin, cy - cs], fill=LIGHT)
        d.rectangle([cx + off - pin, cy + cs,
                     cx + off + pin, cy + cs + size * 0.05], fill=LIGHT)
    return img


def concept_bars(size):
    """Three ascending usage bars: green, amber, red."""
    img = base(size)
    d = ImageDraw.Draw(img)
    cols = [GREEN, AMBER, RED]
    heights = [0.32, 0.50, 0.70]
    n = 3
    gap = size * 0.06
    total_w = size * 0.52
    bw = (total_w - gap * (n - 1)) / n
    x0 = (size - total_w) / 2
    base_y = size * 0.74
    for i in range(n):
        h = size * heights[i]
        x = x0 + i * (bw + gap)
        d.rounded_rectangle([x, base_y - h, x + bw, base_y],
                            radius=int(bw * 0.35), fill=cols[i])
    # baseline
    d.rounded_rectangle([x0 - size * 0.02, base_y,
                         x0 + total_w + size * 0.02, base_y + size * 0.03],
                        radius=int(size * 0.015), fill=MUTED)
    return img


def concept_chip(size, frac=0.72):
    """A GPU/VRAM chip with a horizontal fill meter across it."""
    img = base(size)
    d = ImageDraw.Draw(img)
    cs = size * 0.30
    cx = cy = size / 2
    body = [cx - cs, cy - cs, cx + cs, cy + cs]
    d.rounded_rectangle(body, radius=int(size * 0.07), fill=(28, 33, 47))
    d.rounded_rectangle(body, radius=int(size * 0.07), outline=MUTED,
                        width=max(1, int(size * 0.012)))
    # pins on all four sides
    pin = size * 0.011
    plen = size * 0.05
    for k in (-1.6, -0.8, 0.0, 0.8, 1.6):
        off = k * cs * 0.5
        d.rounded_rectangle([cx + off - pin, cy - cs - plen,
                             cx + off + pin, cy - cs + size * 0.005],
                            radius=int(pin), fill=MUTED)
        d.rounded_rectangle([cx + off - pin, cy + cs - size * 0.005,
                             cx + off + pin, cy + cs + plen],
                            radius=int(pin), fill=MUTED)
        d.rounded_rectangle([cx - cs - plen, cy + off - pin,
                             cx - cs + size * 0.005, cy + off + pin],
                            radius=int(pin), fill=MUTED)
        d.rounded_rectangle([cx + cs - size * 0.005, cy + off - pin,
                             cx + cs + plen, cy + off + pin],
                            radius=int(pin), fill=MUTED)
    # fill meter inside
    inset = cs * 0.42
    mh = cs * 0.5
    track = [cx - inset, cy - mh / 2, cx + inset, cy + mh / 2]
    d.rounded_rectangle(track, radius=int(mh / 2), fill=TRACK)
    fw = (track[2] - track[0]) * frac
    d.rounded_rectangle([track[0], track[1], track[0] + fw, track[3]],
                        radius=int(mh / 2), fill=grad3(frac))
    return img


def concept_combo(size, frac=0.78):
    """Ring gauge with a bold percentage tick + minimalist core."""
    img = base(size)
    d = ImageDraw.Draw(img)
    pad = size * 0.16
    box = [pad, pad, size - pad, size - pad]
    width = int(size * 0.13)
    start, sweep = 130, 280
    d.arc(box, start, start + sweep, fill=TRACK, width=width)
    steps = 200
    filled = int(steps * frac)
    for i in range(filled):
        a0 = start + sweep * i / steps
        a1 = start + sweep * (i + 1) / steps + 1
        d.arc(box, a0, a1, fill=grad3(i / steps), width=width)
    # end cap dot
    ang = math.radians(start + sweep * frac)
    cx = cy = size / 2
    r = (box[2] - box[0]) / 2
    ex = cx + r * math.cos(ang)
    ey = cy + r * math.sin(ang)
    cap = width * 0.62
    d.ellipse([ex - cap, ey - cap, ex + cap, ey + cap], fill=LIGHT)
    # core: stacked memory lines
    lw = size * 0.026
    for j, yy in enumerate((-0.10, 0.0, 0.10)):
        wfac = (0.34, 0.30, 0.22)[j]
        d.rounded_rectangle([cx - size * wfac, cy + size * yy - lw,
                             cx + size * wfac, cy + size * yy + lw],
                            radius=int(lw), fill=LIGHT if j == 0 else MUTED)
    return img


CONCEPTS = {1: concept_ring, 2: concept_bars, 3: concept_chip, 4: concept_combo}


def render(fn, size):
    big = fn(size * SS)
    return big.resize((size, size), Image.LANCZOS)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "concepts"
    if mode == "concepts":
        for i, fn in CONCEPTS.items():
            render(fn, 256).save(f"concept_{i}.png")
            print(f"wrote concept_{i}.png")
    elif mode == "build":
        which = int(sys.argv[2])
        fn = CONCEPTS[which]
        sizes = [256, 128, 64, 48, 32, 24, 16]
        imgs = [render(fn, s) for s in sizes]
        imgs[0].save("VRAMeter.ico", sizes=[(s, s) for s in sizes],
                     append_images=imgs[1:])
        render(fn, 256).save("VRAMeter.png")
        print(f"built VRAMeter.ico from concept {which}")


if __name__ == "__main__":
    main()
