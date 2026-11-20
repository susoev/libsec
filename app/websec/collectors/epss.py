"""EPSS (FIRST.org): вероятность эксплуатации в ближайшие 30 дней. Обновляется раз в сутки;
спрашиваем только наши CVE, у которых нет оценки за последнюю дату."""
import json
from .. import pipeline
from ..net import client

NAME = 'epss'
INTERVAL = 60 * 60
SILENT_H = 0
API = 'https://api.first.org/data/v1/epss'


def run(c, state):
    with client() as cl:
        r = cl.get(API, params={'cve': 'CVE-2021-44228'})
        r.raise_for_status()
        latest = r.json()['data'][0]['date']
        rows = c.execute("select id, epss_date from vulns where relevant=1 and id like 'CVE-%' and (epss_date is null or epss_date < ?)"
                         " and coalesce(json_extract(?, '$.\"' || id || '\"'), '') < ?",
                         (latest, json.dumps(state.get('asked', {})), latest)).fetchall()
        ids = [x['id'] for x in rows]
        n = 0
        asked = state.get('asked', {})
        for k in range(0, len(ids), 80):
            part = ids[k:k + 80]
            r = cl.get(API, params={'cve': ','.join(part), 'limit': 100})
            r.raise_for_status()
            got = {d['cve']: d for d in r.json().get('data') or []}
            for i in part:
                asked[i] = latest
                d = got.get(i)
                if d:
                    pipeline.set_fact(c, i, NAME, {'ids': [i], 'epss': float(d['epss']), 'percentile': float(d['percentile']), 'date': d['date']})
                    n += 1
    state['asked'] = {k: v for k, v in asked.items() if v >= latest}
    return n
