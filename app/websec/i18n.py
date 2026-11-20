"""Языки сайта: английский на websec.in, переводы на двухбуквенных поддоменах (es.websec.in, …).

Интерфейс — словари app/i18n/<lang>.json (ключ — английская строка). Тексты ИИ-разборов переводит
websec.ai (таблица analysis_tr), исходные описания CVE остаются на английском.
"""
import json, time
from pathlib import Path

from markupsafe import Markup

DOMAIN = 'websec.in'
BRAND = 'WebSec'
GITHUB = 'https://github.com/susoev/websec.in'
DEFAULT = 'en'
# порядок = порядок в переключателе; hreflang / og:locale / имя на своём языке
LANGS = {
    'en': {'name': 'English', 'hreflang': 'en', 'og': 'en_US'},
    'es': {'name': 'Español', 'hreflang': 'es', 'og': 'es_ES'},
    'pt': {'name': 'Português', 'hreflang': 'pt', 'og': 'pt_BR'},
    'fr': {'name': 'Français', 'hreflang': 'fr', 'og': 'fr_FR'},
    'de': {'name': 'Deutsch', 'hreflang': 'de', 'og': 'de_DE'},
    'ru': {'name': 'Русский', 'hreflang': 'ru', 'og': 'ru_RU'},
    'zh': {'name': '中文', 'hreflang': 'zh-Hans', 'og': 'zh_CN'},
    'ja': {'name': '日本語', 'hreflang': 'ja', 'og': 'ja_JP'},
}
TR_LANGS = [l for l in LANGS if l != DEFAULT]
DIR = Path(__file__).resolve().parent.parent / 'i18n'
T = {l: json.loads((DIR / f'{l}.json').read_text()) for l in TR_LANGS if (DIR / f'{l}.json').exists()}


def host_lang(host):
    sub = (host or '').split(':')[0].lower().removesuffix('.' + DOMAIN)
    return sub if sub in T else DEFAULT


def origin(lang):
    return f'https://{DOMAIN}' if lang == DEFAULT else f'https://{lang}.{DOMAIN}'


def gettext(lang):
    d = T.get(lang, {})

    def _(s, /, **kw):
        m = Markup(d.get(s) or s)  # строки наши, из словаря: разметка доверенная
        return m.format(**kw) if kw else m  # Markup.format экранирует подставляемые значения
    return _


def ago(t, lang):
    if not t:
        return ''
    _ = gettext(lang)
    d = time.time() - t
    if d < 3600:
        return _('{n} min ago', n=max(1, int(d // 60)))
    if d < 86400:
        return _('{n} h ago', n=int(d // 3600))
    if d < 86400 * 60:
        return _('{n} d ago', n=int(d // 86400))
    return time.strftime('%Y-%m-%d', time.gmtime(t))


# ---------- перевод ИИ-разбора (пишет websec.ai, читает сайт)
TR_FIELDS = ('headline', 'summary', 'affects', 'preconditions', 'action', 'score_reasoning', 'vuln_type')
TR_VERSION = 1


def tr_source(an):
    return {k: an.get(k) for k in TR_FIELDS if an.get(k)}


def tr_hash(an):
    import hashlib
    return hashlib.sha1(json.dumps([TR_VERSION, tr_source(an)], ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def reason(s, lang):
    """priority_reason из pipeline.priority() -> язык страницы."""
    import re
    _ = gettext(lang)
    out = []
    for part in (s or '').split('; '):
        m = re.fullmatch(r'CVSS (\S+) (\w+)', part)
        n = re.fullmatch(r'(\w+) per (.+)', part)
        if m:
            out.append(Markup('CVSS {} {}').format(m[1], _(m[2])))
        elif n:
            out.append(_('{sev} per {src}', sev=_(n[1]), src=n[2]))
        else:
            out.append(Markup.escape(T.get(lang, {}).get(part, part)))
    return Markup('; ').join(out)
