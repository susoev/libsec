"""OSV.dev: пакеты экосистем (Packagist, PyPI, npm, Go, Maven, RubyGems) — GHSA, PYSEC, GO-… с точными версиями.

Бэкфилл: по каждому пакету каталога POST api.osv.dev/v1/query (вся история пакета).
Дельты: <экосистема>/modified_id.csv из бакета OSV (новые сверху) с If-None-Match, читаем до курсора,
затем <экосистема>/<id>.json. MAL-* (вредоносные пакеты npm/PyPI) пропускаем.
"""
import logging
from .. import catalog, normalize, pipeline
from ..net import client, cond_get

NAME = 'osv'
INTERVAL = 15 * 60
SILENT_H = 0  # по нашим пакетам может легитимно неделями не быть нового
BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
log = logging.getLogger(NAME)


def _take(c, rec):
    f = normalize.parse_osv(rec)
    if not (f['products'] or pipeline.known_id(c, f['ids'])):
        return 0
    return int(pipeline.ingest(c, NAME, rec['id'], f'https://osv.dev/vulnerability/{rec["id"]}', rec, f))


def backfill(c, cl, state):
    done = set(state.get('pkgs', []))
    n = 0
    for (eco, name), slug in sorted(catalog.OSV_INDEX.items()):
        key = f'{eco}/{name}'
        if key in done:
            continue
        token = None
        ids = []
        while True:
            body = {'package': {'ecosystem': eco, 'name': name}}
            if token:
                body['page_token'] = token
            r = cl.post('https://api.osv.dev/v1/query', json=body)
            r.raise_for_status()
            j = r.json()
            ids += [v['id'] for v in j.get('vulns') or []]
            token = j.get('next_page_token')
            if not token:
                break
        # query отдаёт урезанные записи — полные берём по id
        for i in ids:
            r = cl.get(f'https://api.osv.dev/v1/vulns/{i}')
            if r.status_code == 200:
                n += _take(c, r.json())
        done.add(key)
        state['pkgs'] = sorted(done)
        pipeline.flush(c)
        c.commit()
        log.info('backfill %s: %d', key, len(ids))
    return n


def run(c, state):
    n = 0
    cur = state.setdefault('cursor', {})
    with client(120) as cl:
        first = not cur
        for eco in catalog.OSV_ECOS:
            r = cond_get(cl, f'{BUCKET}/{eco}/modified_id.csv', state, key=eco)
            if r is None:
                continue
            last = cur.get(eco, '')
            top = None
            fresh = []
            for line in r.text.splitlines():
                if ',' not in line:
                    continue
                mod, vid = line.split(',', 1)
                top = top or mod
                if mod <= last:
                    break
                if not vid.startswith('MAL-'):
                    fresh.append(vid)
                if first:  # при первом запуске только запоминаем курсор, историю даст бэкфилл
                    break
            if not first:
                for vid in fresh[:2000]:
                    rr = cl.get(f'{BUCKET}/{eco}/{vid}.json')
                    if rr.status_code == 200:
                        n += _take(c, rr.json())
            if top:
                cur[eco] = top
        n += backfill(c, cl, state)
    return n
