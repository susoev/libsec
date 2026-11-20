"""Все ключи интерфейса: из шаблонов (_('…')) + строки, которые подставляет код. -> JSON-список в stdout."""
import json, re, sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / 'app'
sys.path.insert(0, str(APP))
from libsec import catalog  # noqa: E402

keys = []
for f in sorted((APP / 'templates').glob('*.html')):
    keys += [k.replace("\\'", "'") for k in re.findall(r"""_\('((?:[^'\\]|\\.)*)'""", f.read_text())]
keys += [k.replace("\\'", "'") for k in re.findall(r"""_\('((?:[^'\\]|\\.)*)'""", (APP / 'libsec' / 'web.py').read_text())]
keys += ['{n} min ago', '{n} h ago', '{n} d ago', 'exploited in the wild (CISA KEV)', 'no CVSS yet', '{sev} per {src}',
         'critical', 'high', 'medium', 'low', 'none', 'unrated', 'moderate',
         'network', 'adjacent', 'local', 'physical', 'unknown', 'likely', 'possible', 'unlikely',
         'What to do:', 'web stack vulnerabilities', 'New vulnerabilities in PHP, Python, MySQL, nginx, Apache and other web-server software']
keys += list(catalog.CATS.values())
print(json.dumps(list(dict.fromkeys(keys)), ensure_ascii=False, indent=0))
