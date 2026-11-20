"""Перевести недостающие ключи интерфейса через локальный claude -p и проверить плейсхолдеры/теги.
   python3 tools/i18n_gen.py LANG [LANG…]   (ключи — tools/i18n_keys.py; результат — app/i18n/LANG.json)"""
import json, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAMES = {'es': 'Spanish', 'pt': 'Portuguese (Brazilian)', 'fr': 'French', 'de': 'German', 'ru': 'Russian',
         'zh': 'Simplified Chinese', 'ja': 'Japanese'}
CLI = os.environ.get('LIBSEC_CLAUDE', str(Path.home() / '.local/bin/claude'))


def marks(s):
    return sorted(re.findall(r'\{\w+\}|<[^>]+>', s))  # сущности (&amp;) переводчик вправе убрать


def gen(lang):
    keys = json.loads(subprocess.check_output([sys.executable, str(ROOT / 'tools/i18n_keys.py')]))
    path = ROOT / 'app/i18n' / f'{lang}.json'
    have = json.loads(path.read_text()) if path.exists() else {}
    todo = [k for k in keys if k not in have]
    if todo:
        prompt = (f"Translate the user-interface strings of a web-security vulnerability tracker (site WebSec, websec.in) from English to {NAMES[lang]}.\n"
                  "Audience: system administrators and developers. Use the established security terminology of that language; keep these unchanged: "
                  "CVE, CVSS, EPSS, CISA KEV, KEV, GHSA, OSV, CNA, CPE, RSS, JSON, API, OpenAPI, AI, product names, code, URLs.\n"
                  "Preserve exactly every placeholder like {n} and every HTML tag/entity (<b>, </b>, <a href=\"…\">, &amp;, <code>, <i>).\n"
                  "Short labels (critical, high, low, network, likely…) are badge/enum values: translate as short adjectives/nouns, lowercase where natural.\n"
                  "'{n} d ago' means days ago, '{n} h ago' hours ago. 'Every' is a table column: run interval.\n"
                  "Return ONLY a JSON object mapping each English string to its translation, no prose, no code fences.\n\n"
                  + json.dumps(todo, ensure_ascii=False))
        p = subprocess.run([CLI, '-p', '--output-format', 'json', '--tools', '', '--setting-sources', '', '--strict-mcp-config',
                            '--no-session-persistence'], input=prompt, capture_output=True, text=True, timeout=1800,
                           env={**os.environ, 'SEC_TG': '0', 'LIBSEC_JOB': '1'}, cwd='/tmp')
        res = json.loads(p.stdout)['result'].strip()
        got = json.loads(res[res.find('{'):res.rfind('}') + 1])
        for k in todo:
            v = got.get(k)
            if isinstance(v, str) and v.strip() and marks(v) == marks(k):
                have[k] = v
            else:
                print(lang, 'ПРОПУСК', repr(k), '->', repr(v))
    have = {k: have[k] for k in keys if k in have}
    path.write_text(json.dumps(have, ensure_ascii=False, indent=1) + '\n')
    print(lang, len(have), '/', len(keys))


if __name__ == '__main__':
    for l in sys.argv[1:]:
        gen(l)
