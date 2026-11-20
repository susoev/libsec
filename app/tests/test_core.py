"""Быстрые проверки парсеров на сохранённых снимках: python -m tests.test_core (из app/)."""
import json
from pathlib import Path
from libsec import catalog, normalize
from libsec.collectors import nginx

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


if __name__ == '__main__':
    for k, fn in list(globals().items()):
        if k.startswith('test_'):
            fn()
            print('ok', k)
