"""CVE List V5 (github.com/CVEProject/cvelistV5): delta-релизы вместо git clone.

Каждый час в релизе cve_<день>_<HH>00Z лежит <день>_delta_CVEs_at_<HH>00Z.zip — все CVE, изменённые с полуночи UTC
(накопительно). После полуночи появляется cve_<день>_at_end_of_day. Бэкфилл — по end_of_day за BACKFILL дней.
В базу берём только записи, совпавшие с каталогом, или уже известные нам уязвимости.
"""
import io, json, logging, zipfile
from datetime import datetime, timedelta, timezone
from .. import normalize, pipeline
from ..net import client

NAME = 'cvelist'
INTERVAL = 15 * 60
SILENT_H = 6
BACKFILL = 30
BASE = 'https://github.com/CVEProject/cvelistV5/releases/download'
log = logging.getLogger(NAME)


def _zip(cl, tag, asset):
    r = cl.get(f'{BASE}/{tag}/{asset}')
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return zipfile.ZipFile(io.BytesIO(r.content))


def process(c, z):
    n = 0
    for name in z.namelist():
        if not name.endswith('.json'):
            continue
        try:
            rec = json.loads(z.read(name))
            f = normalize.parse_cve(rec)
        except Exception as e:  # битая запись не должна ронять весь архив
            log.warning('parse %s: %s', name, e)
            continue
        if not f['primary']:
            continue
        if f['products'] and pipeline.low_noise(f) and not pipeline.known_id(c, f['ids']):
            continue  # ядро Linux и т.п.: мелкие CVE не храним вовсе (KEV/EPSS подтянут их позже через cveapi)
        if f['products'] or pipeline.known_id(c, f['ids']):
            if pipeline.ingest(c, NAME, f['primary'], f'https://www.cve.org/CVERecord?id={f["primary"]}', rec, f):
                n += 1
    return n


def run(c, state):
    now = datetime.now(timezone.utc)
    done = set(state.get('days', []))
    n = 0
    with client(120) as cl:
        for i in range(BACKFILL, 0, -1):
            d = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            if d in done:
                continue
            z, final = _zip(cl, f'cve_{d}_at_end_of_day', f'{d}_delta_CVEs_at_end_of_day.zip'), True
            if z is None:
                z, final = _zip(cl, f'cve_{d}_2300Z', f'{d}_delta_CVEs_at_2300Z.zip'), i > 1
            if z is None:
                log.info('нет архива за %s', d)
                if i > 1:
                    done.add(d)
                continue
            k = process(c, z)
            n += k
            log.info('день %s: %d', d, k)
            if final:
                done.add(d)
            pipeline.flush(c)
            c.commit()
        # сегодня: самый свежий часовой архив
        d = now.strftime('%Y-%m-%d')
        for hh in range(now.hour, -1, -1):
            tag, asset = f'cve_{d}_{hh:02d}00Z', f'{d}_delta_CVEs_at_{hh:02d}00Z.zip'
            if state.get('today') == asset:
                break
            z = _zip(cl, tag, asset)
            if z is None:
                continue
            n += process(c, z)
            state['today'] = asset
            break
    state['days'] = sorted(d for d in done if d >= (now - timedelta(days=BACKFILL + 2)).strftime('%Y-%m-%d'))
    return n
