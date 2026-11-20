"""Первоисточник nginx: nginx.org/en/security_advisories.html (HTML, ETag). Даёт CVE, серьёзность по оценке nginx
и точные границы уязвимых/исправленных версий. Пример блока — tests/fixtures/nginx_advisories.html."""
import html, re
from .. import pipeline
from ..net import client, cond_get

NAME = 'nginx'
INTERVAL = 60 * 60
SILENT_H = 0
URL = 'https://nginx.org/en/security_advisories.html'
LI = re.compile(r'<li><p>(.*?)</p></li>', re.S)


def parse(page):
    out = []
    for m in LI.finditer(page):
        parts = [html.unescape(re.sub(r'<[^>]+>', '', p)).strip() for p in m.group(1).split('<br>')]
        cves = re.findall(r'CVE-\d{4}-\d{4,}', m.group(1))
        if not cves or not parts:
            continue
        item = {'title': parts[0], 'cves': cves}
        for p in parts[1:]:
            k, _, v = p.partition(':')
            k = k.strip().lower()
            if k in ('severity', 'not vulnerable', 'vulnerable'):
                item[k.replace(' ', '_')] = v.strip()
        adv = re.search(r'<a href="([^"]+)">Advisory</a>', m.group(1))
        item['advisory'] = adv.group(1) if adv else None
        out.append(item)
    return out


def run(c, state):
    with client() as cl:
        r = cond_get(cl, URL, state)
    if r is None:
        return 0
    n = 0
    for it in parse(r.text):
        fixed = [v.strip().rstrip('+') for v in (it.get('not_vulnerable') or '').split(',') if v.strip() and v.strip() != 'none']
        for cve in it['cves']:
            f = {'ids': [cve], 'primary': cve, 'products': ['nginx'], 'title': f'nginx: {it["title"]}',
                 'vendor_severity': it.get('severity'),
                 'refs': [{'url': it['advisory'], 'tags': ['vendor-advisory'], 'by': 'nginx.org'}] if it.get('advisory') else [],
                 'affected': [{'product': 'nginx', 'name': 'nginx', 'ranges': [it.get('vulnerable', '')], 'fixed': fixed, 'by': 'nginx.org'}]}
            n += int(pipeline.ingest(c, NAME, cve, URL, it, f))
    return n
