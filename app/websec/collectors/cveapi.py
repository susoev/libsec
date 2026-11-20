"""Догрузка CVE-записи из CVE Services (cveawg.mitre.org) для уязвимостей, пришедших из OSV/KEV/вендоров без записи cvelist
(например, старые CVE из KEV или GHSA с CVE-алиасом, чья запись не попала в наше окно бэкфилла)."""
import json
from .. import normalize, pipeline
from ..net import client

NAME = 'cveapi'
INTERVAL = 10 * 60
SILENT_H = 0
BATCH = 200


def run(c, state):
    ids = [r[0] for r in c.execute(
        "select v.id from vulns v where v.id like 'CVE-%' and v.products != '[]'"
        " and not exists(select 1 from facts f where f.vuln_id=v.id and f.source in ('cvelist','cveapi'))"
        " and v.id not in (select value from json_each(?)) order by v.feed_ts desc limit ?",
        (json.dumps(state.get('missing', [])), BATCH))]
    n = 0
    missing = set(state.get('missing', []))
    with client() as cl:
        for i in ids:
            r = cl.get(f'https://cveawg.mitre.org/api/cve/{i}')
            if r.status_code == 404:
                missing.add(i)
                continue
            r.raise_for_status()
            rec = r.json()
            f = normalize.parse_cve(rec)
            n += int(pipeline.ingest(c, NAME, i, f'https://www.cve.org/CVERecord?id={i}', rec, f))
    state['missing'] = sorted(missing)[-2000:]
    return n
