"""Быстрые проверки парсеров на сохранённых снимках: python -m tests.test_core (из app/)."""
import json
from pathlib import Path
from websec import catalog, normalize
from websec.collectors import nginx

FX = Path(__file__).parent / 'fixtures'


def test_cvss3():
    assert normalize.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') == 9.8
    assert normalize.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N') == 6.1
    assert normalize.cvss3_score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H') == 7.8


def test_catalog():
    assert catalog.match_affected('PHP Group', 'PHP') == {'php'}
    assert catalog.match_affected('F5', 'NGINX Open Source') == {'nginx'}
    assert catalog.match_affected('Apache Software Foundation', 'Apache Tomcat') == {'tomcat'}
    assert catalog.match_affected('Red Hat', 'Red Hat Enterprise Linux 9', 'nginx') == {'nginx'}
    assert catalog.match_affected(ecosystem='Packagist', osv_name='laravel/framework') == {'laravel'}
    assert catalog.match_affected('Apache Software Foundation', 'Apache TomEE') == set()
    assert catalog.match_affected('php', 'frankenphp') == set()
    assert catalog.match_kev('PHP Group', 'PHP') == {'php'}


def test_nginx_parser():
    items = nginx.parse((FX / 'nginx_advisories.html').read_text())
    assert items, 'парсер nginx.org ничего не нашёл — изменилась разметка?'
    for it in items:
        assert it['cves'] and it['title'] and 'not_vulnerable' in it and 'vulnerable' in it


def test_osv_ranges():
    rec = {'id': 'GHSA-x', 'aliases': ['CVE-2026-12345'], 'summary': 's', 'details': 'd',
           'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'Django'},
                         'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '5.0'}, {'fixed': '5.0.9'}]}]}]}
    f = normalize.parse_osv(rec)
    assert f['primary'] == 'CVE-2026-12345' and f['products'] == ['django']
    assert f['affected'][0]['ranges'] == ['>= 5.0, < 5.0.9'] and f['affected'][0]['fixed'] == ['5.0.9']


def test_i18n():
    """Все строки интерфейса переведены на все языки, плейсхолдеры и теги на месте; язык по Host."""
    import json, re, subprocess, sys
    from pathlib import Path
    from websec import i18n
    root = Path(__file__).resolve().parents[2]
    keys = json.loads(subprocess.check_output([sys.executable, str(root / 'tools/i18n_keys.py')]))
    marks = lambda s: sorted(re.findall(r'\{\w+\}|<[^>]+>', s))
    for l in i18n.TR_LANGS:
        d = i18n.T[l]
        miss = [k for k in keys if k not in d]
        assert not miss, (l, miss[:3])
        bad = [k for k in keys if marks(d[k]) != marks(k)]
        assert not bad, (l, bad[:3])
    assert i18n.host_lang('ru.websec.in') == 'ru' and i18n.host_lang('websec.in') == 'en' and i18n.host_lang('xx.websec.in') == 'en'
    assert str(i18n.gettext('de')('{n} min ago', n=5)).startswith('vor 5')
    assert str(i18n.reason('CVSS 9.8 critical; EPSS 97%', 'ru')).startswith('CVSS 9.8 ')
    assert '9.8' in str(i18n.gettext('ru')('CVSS {s} ({sev}) by {by}', s=9.8, sev='x', by='CNA'))  # {s} не конфликтует с аргументом


def test_tr_ok():
    from websec.ai import tr_ok
    src = {'summary': 'Fixed in 1.2.3 and 2.0.', 'preconditions': ['a', 'b']}
    assert tr_ok(src, {'summary': 'Corregido en 1.2.3 y 2.0.', 'preconditions': ['x', 'y']})
    assert not tr_ok(src, {'summary': 'Corregido en 1.2.4 y 2.0.', 'preconditions': ['x', 'y']})
    assert not tr_ok(src, {'summary': 'Corregido en 1.2.3 y 2.0.', 'preconditions': ['x']})


def test_web():
    """Смоук сайта и API на живой БД (если она есть): страницы на языках, свежие уязвимости, og-картинки, конверт API."""
    from websec.db import DB
    if not DB.exists():
        return
    from fastapi.testclient import TestClient
    from websec.web import app, db
    c = TestClient(app)
    ids = [r[0] for r in db().execute('select id from vulns where listed=1 order by feed_ts desc limit 40')]
    ids += [r[0] for r in db().execute("select distinct vuln_id from events where type='scored' limit 20")]
    for host in ('websec.in', 'ru.websec.in', 'zh.websec.in'):
        h = {'host': host}
        for path in ['/', '/how', '/about', '/products', '/product/php', '/status', '/og/site.png', '/og/page/how.png',
                     '/og/product/php.png'] + [f'/vuln/{i}' for i in ids[:5]] + [f'/og/vuln/{i}.png' for i in ids[:3]]:
            r = c.get(path, headers=h)
            assert r.status_code == 200, (host, path, r.status_code)
    for i in ids:
        assert c.get(f'/vuln/{i}', headers={'host': 'de.websec.in'}).status_code == 200, i
    r = c.get('/', headers={'host': 'websec.in'}).text
    assert 'summary_large_image' in r and 'https://websec.in/og/site.png' in r
    d = c.get('/api/high10?n=3', headers={'host': 'websec.in'}).json()
    assert d['result'] is True and d['doc'].endswith('/api/doc') and len(d['items']) <= 3
    assert all(x['priority'] in ('CRITICAL', 'HIGH') for x in d['items'])
    d = c.get('/api/high10?n=500', headers={'host': 'websec.in'})
    assert d.status_code == 400 and d.json()['result'] is False
    assert c.get('/api/high10', headers={'host': 'ru.websec.in'}, follow_redirects=False).status_code == 301
    d = c.get('/api/v1/status', headers={'host': 'websec.in'}).json()
    assert d['result'] is True and d['items'] and {'last_attempt_at', 'last_success_at', 'interval_seconds', 'enabled',
                                                   'consecutive_failures', 'last_error', 'last_data_change_at'} <= set(d['items'][0])


if __name__ == '__main__':
    for k, fn in list(globals().items()):
        if k.startswith('test_'):
            fn()
            print('ok', k)
