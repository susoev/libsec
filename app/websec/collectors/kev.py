"""CISA Known Exploited Vulnerabilities: уязвимость эксплуатируется в реальных атаках."""
from .. import normalize, pipeline
from ..net import client, cond_get

NAME = 'kev'
INTERVAL = 60 * 60
SILENT_H = 0
URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def run(c, state):
    with client() as cl:
        r = cond_get(cl, URL, state)
    if r is None:
        return 0
    j = r.json()
    state['catalogVersion'] = j.get('catalogVersion')
    n = 0
    for e in j.get('vulnerabilities') or []:
        f = normalize.parse_kev(e)
        if f['products'] or pipeline.known_id(c, f['ids']):
            n += int(pipeline.ingest(c, NAME, e['cveID'], f'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={e["cveID"]}', e, f))
    return n
