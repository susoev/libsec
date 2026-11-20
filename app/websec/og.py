"""Картинки-превью для соцсетей и мессенджеров (og:image, twitter:image): 1200×630 PNG.

Рисуются по запросу (Pillow) и кэшируются в памяти процесса. Шрифт — Noto Sans CJK (пакет fonts-noto-cjk):
в нём латиница, кириллица, китайский и японский. Строки — через i18n, ключи собирает tools/i18n_keys.py.
"""
import io
import re
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630
PAD = 64
BG, INK, MUTE, LINE, ACC = '#0f1115', '#e7e9ee', '#9aa3b2', '#272b35', '#6f9bff'
PRIO = {'CRITICAL': '#e5484d', 'HIGH': '#f76b15', 'MEDIUM': '#d4a72c', 'LOW': '#30a46c', 'UNRATED': '#6b7280'}
KEV = '#8e4ec6'
FONT_DIR = '/usr/share/fonts/opentype/noto/'
CJK = re.compile(r'[⺀-鿿가-힯豈-﫿＀-￯]')


@lru_cache(maxsize=64)
def font(size, bold=False, lang='en'):
    # индекс в .ttc: 0 — японское начертание (оно же для латиницы и кириллицы), 2 — упрощённый китайский
    return ImageFont.truetype(FONT_DIR + ('NotoSansCJK-Bold.ttc' if bold else 'NotoSansCJK-Regular.ttc'), size, index=2 if lang == 'zh' else 0)


def wrap(d, text, f, width, max_lines):
    """Перенос по словам (CJK — по символам). Не влезло — многоточие в последней строке."""
    toks = re.findall(CJK.pattern + r'|\S+|\s+', text or '')
    lines, cur = [], ''
    for t in toks:
        if not lines and not cur and t.isspace():
            continue
        if d.textlength(cur + t, font=f) <= width:
            cur += t
            continue
        if t.isspace():
            continue
        if cur.strip():
            lines.append(cur.rstrip())
        cur = t
        while d.textlength(cur, font=f) > width:  # одно слово шире строки
            i = len(cur) - 1
            while i > 1 and d.textlength(cur[:i], font=f) > width:
                i -= 1
            lines.append(cur[:i])
            cur = cur[i:]
    if cur.strip():
        lines.append(cur.rstrip())
    if len(lines) > max_lines:
        last = lines[max_lines - 1]
        while last and d.textlength(last + '…', font=f) > width:
            last = last[:-1]
        lines = lines[:max_lines - 1] + [last.rstrip(' ,.;:') + '…']
    return lines


def chip(d, x, y, text, f, fill, color='#ffffff', outline=None):
    """Плашка с текстом, возвращает её правый край."""
    w = d.textlength(text, font=f)
    h = f.size + 22
    d.rounded_rectangle([x, y, x + w + 36, y + h], radius=12, fill=fill, outline=outline, width=2 if outline else 0)
    d.text((x + 18, y + h / 2), text, font=f, fill=color, anchor='lm')
    return x + w + 36


@lru_cache(maxsize=256)
def card(lang, host, title, label='', sub='', chips=(), accent=ACC):
    """chips: ((текст, заливка), …); заливка None — контурная плашка. Кэш по всем аргументам."""
    im = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, H - 12, W, H], fill=accent)
    # логотип: щит + websec
    s = 1.6
    d.polygon([(PAD + 16 * s, 58 + 2 * s), (PAD + 4 * s, 58 + 7 * s), (PAD + 4 * s, 58 + 15 * s), (PAD + 16 * s, 58 + 30 * s),
               (PAD + 28 * s, 58 + 15 * s), (PAD + 28 * s, 58 + 7 * s)], fill=ACC)
    fl = font(40, True)
    x = PAD + 56
    d.text((x, 82), 'web', font=fl, fill=INK, anchor='lm')
    d.text((x + d.textlength('web', font=fl), 82), 'sec', font=fl, fill=ACC, anchor='lm')
    d.text((W - PAD, 82), host, font=font(30, lang=lang), fill=MUTE, anchor='rm')

    y = 160
    if label:
        d.text((PAD, y), label, font=font(32, lang=lang), fill=MUTE)
        y += 58
    room = (H - 140 if chips else H - 70) - y - (60 if sub else 0)
    for size in (64, 56, 50, 44):
        ft = font(size, True, lang)
        lh = int(size * 1.28)
        lines = wrap(d, title, ft, W - 2 * PAD, max(1, room // lh))
        if len(wrap(d, title, ft, W - 2 * PAD, 99)) * lh <= room:
            break
    for ln in lines:
        d.text((PAD, y), ln, font=ft, fill=INK)
        y += lh
    if sub:
        fs = font(30, lang=lang)
        d.text((PAD, y + 12), wrap(d, sub, fs, W - 2 * PAD, 1)[0], font=fs, fill=MUTE)
    if chips:
        x, fc = PAD, font(28, True, lang)
        for text, fill in chips:
            if x + d.textlength(text, font=fc) + 36 > W - PAD:
                break
            x = chip(d, x, H - 110, text, fc, fill or BG, INK if fill is None else '#ffffff', LINE if fill is None else None) + 14
    buf = io.BytesIO()
    im.save(buf, 'PNG', optimize=True)
    return buf.getvalue()
