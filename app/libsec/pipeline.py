"""Нормализация и дедупликация: raw_items -> facts -> vulns (+ события, очередь TG).

Одна уязвимость = одна строка vulns с каноническим ID (CVE, если он есть, иначе GHSA/OSV).
Все ID источников — в aliases. Поля vulns каждый раз пересчитываются из facts всех источников.
"""
import hashlib, logging, time
from datetime import datetime, timezone
from . import catalog
from .db import dumps, loads
from .normalize import band, CVE_RE

log = logging.getLogger('pipeline')
FEED_DAYS = 45          # в ленту: опубликовано или попало в KEV за последние N дней
ALERT_FRESH = 36 * 3600
VENDOR_SOURCES = ('nginx',)  # события старше — бэкфилл, в Telegram не шлём
_dirty = set()


def ts(iso):
    if not iso:
        return None
    if isinstance(iso, (int, float)):
        return float(iso)
    s = str(iso).strip().replace('Z', '+00:00')
    if len(s) == 10:
        s += 'T00:00:00+00:00'
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def h(o):
    return hashlib.sha1(dumps(o).encode()).hexdigest()


# ---------- приём
def known_id(c, ids):
    for i in ids:
        r = c.execute('select vuln_id from aliases where alias=?', (i,)).fetchone()
        if r:
            return r[0]
    return None


def ingest(c, source, external_id, url, payload, facts):
    """Сохранить сырую запись и факты. -> True, если запись новая или изменилась."""
    hs = h(payload)
    old = c.execute('select hash from raw_items where source=? and external_id=?', (source, external_id)).fetchone()
    if old and old[0] == hs:
        return False
    c.execute('insert or replace into raw_items(source,external_id,url,hash,payload,fetched_at,processed) values(?,?,?,?,?,?,1)',
              (source, external_id, url, hs, dumps(payload), time.time()))
    attach(c, source, external_id, facts)
    return True


def attach(c, source, external_id, facts):
    ids = [i for i in dict.fromkeys(facts.get('ids') or []) if i]
    existing = {r[0] for i in ids for r in c.execute('select vuln_id from aliases where alias=?', (i,))}
    primary = facts.get('primary')
    if primary:
        canon = primary
    elif existing:
        canon = sorted(existing, key=lambda v: (not CVE_RE.match(v), v))[0]
    else:
        canon = ids[0]
    for v in existing - {canon}:
        if CVE_RE.match(v):
            continue  # другой CVE — отдельная уязвимость, даже если advisory упоминает оба
        rename(c, v, canon)
    for i in ids + [canon]:
        if CVE_RE.match(i) and i != canon:
            c.execute('insert or ignore into aliases(alias,vuln_id) values(?,?)', (i, canon))
        else:
            c.execute('insert or replace into aliases(alias,vuln_id) values(?,?)', (i, canon))
    c.execute('insert or replace into facts(vuln_id,source,external_id,data,updated) values(?,?,?,?,?)',
              (canon, source, external_id, dumps(facts), time.time()))
    _dirty.add(canon)
    return canon


def rename(c, old, new):
    """GHSA-… получил CVE (или два ID оказались одной уязвимостью): переносим всё на new."""
    log.info('merge %s -> %s', old, new)
    for t, col in (('facts', 'vuln_id'), ('aliases', 'vuln_id'), ('vuln_products', 'vuln_id'), ('events', 'vuln_id'),
                   ('tg_queue', 'vuln_id')):
        c.execute(f'update or ignore {t} set {col}=? where {col}=?', (new, old))
        c.execute(f'delete from {t} where {col}=?', (old,))
    a = c.execute('select * from analysis where vuln_id=?', (old,)).fetchone()
    if a and not c.execute('select 1 from analysis where vuln_id=?', (new,)).fetchone():
        c.execute('update analysis set vuln_id=? where vuln_id=?', (new, old))
    c.execute('delete from analysis where vuln_id=?', (old,))
    c.execute('delete from vulns where id=?', (old,))
    _dirty.discard(old)
    _dirty.add(new)


def set_fact(c, vid, source, data):
    c.execute('insert or replace into facts(vuln_id,source,external_id,data,updated) values(?,?,?,?,?)',
              (vid, source, vid, dumps(data), time.time()))
    _dirty.add(vid)


# ---------- пересчёт
CVSS_RANK = {('CNA', '3.1'): 0, ('CNA', '3.0'): 1, ('CNA', '4.0'): 2, ('CISA-ADP', '3.1'): 3, ('GHSA', '3.1'): 4}


def pick_cvss(lst):
    lst = [x for x in lst if x.get('score') is not None and x.get('version') != '2.0'] or [x for x in lst if x.get('score') is not None]
    if not lst:
        return None
    return sorted(lst, key=lambda x: (CVSS_RANK.get((x['by'], x['version']), 9), -x['score']))[0]


def priority(v):
    """Правило до ИИ: насколько срочно, по CVSS + KEV + EPSS."""
    sev = v['cvss_severity']
    reasons = []
    order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if v['kev']:
        reasons.append('exploited in the wild (CISA KEV)')
        p = 'CRITICAL' if sev in (None, 'HIGH', 'CRITICAL') else 'HIGH'
    elif sev in order:
        p = sev
        reasons.append(f'CVSS {v["cvss_score"]} {sev.lower()}')
        if (v['epss'] or 0) >= 0.5 and order.index(p) < 2:
            p = order[order.index(p) + 1]
            reasons.append(f'EPSS {v["epss"]:.0%}')
    else:
        p = 'UNRATED'
        reasons.append('no CVSS yet')
    if (v['epss'] or 0) >= 0.1 and 'EPSS' not in ' '.join(reasons):
        reasons.append(f'EPSS {v["epss"]:.0%}')
    return p, '; '.join(reasons)


def high_only_ok(v):
    """Продукты с потоком мелких CVE (ядро): только KEV, CVSS >= 9 или сетевой вектор с CVSS >= 8."""
    sc = v['cvss_score'] or 0
    return bool(v['kev'] or sc >= 9 or (sc >= 8 and 'AV:N' in (v['cvss_vector'] or '')) or (v['epss'] or 0) >= 0.1)



def low_noise(f):
    """Факты только по high_only-продуктам и без высокой оценки -> не храним."""
    if not all(catalog.BY_SLUG[p].get('high_only') for p in f['products'] if p in catalog.BY_SLUG):
        return False
    best = max((x for x in f.get('cvss') or [] if x.get('score') is not None), key=lambda x: x['score'], default=None)
    v = {'kev': 0, 'epss': None, 'cvss_score': best['score'] if best else None, 'cvss_vector': best.get('vector') if best else None}
    return not high_only_ok(v)


def prune(c):
    """Удалить нерелевантные записи high_only-продуктов (не KEV, без высокой оценки)."""
    ids = [r[0] for r in c.execute('select id from vulns where relevant=0 and kev=0').fetchall()]
    n = 0
    for vid in ids:
        prods = loads(c.execute('select products from vulns where id=?', (vid,)).fetchone()[0], [])
        if prods and all(catalog.BY_SLUG.get(p, {}).get('high_only') for p in prods):
            for t, col in (('facts', 'vuln_id'), ('aliases', 'vuln_id'), ('vuln_products', 'vuln_id'), ('events', 'vuln_id'), ('vulns', 'id')):
                c.execute(f'delete from {t} where {col}=?', (vid,))
            c.execute("delete from raw_items where external_id=? and source in ('cvelist','cveapi')", (vid,))
            n += 1
    return n


def recompute(c, vid):
    rows = c.execute('select source, data from facts where vuln_id=?', (vid,)).fetchall()
    if not rows:
        return
    F = [(r['source'], loads(r['data'], {})) for r in rows]
    cve = [f for s, f in F if s in ('cvelist', 'cveapi')]
    osv = [f for s, f in F if s == 'osv']
    kev = next((f['kev'] for s, f in F if s == 'kev' and f.get('kev')), None)
    epss = next((f for s, f in F if s == 'epss'), None)
    vend = [f for s, f in F if s in VENDOR_SOURCES]
    base = cve + osv
    rich = cve + osv + vend
    ids = sorted({i for _, f in F for i in f.get('ids') or []} | {vid})
    state = 'PUBLISHED'
    if cve and cve[0].get('state') == 'REJECTED':
        state = 'REJECTED'
    elif not cve and osv and all(f.get('state') == 'WITHDRAWN' for f in osv):
        state = 'WITHDRAWN'
    title = next((f['title'] for f in osv if f.get('title')), '') or next((f['title'] for f in cve if f.get('title')), '') \
        or next((f['title'] for s, f in F if s == 'kev' and f.get('title')), '')
    desc = next((f['description'] for f in cve if f.get('description')), '') or next((f['description'] for f in osv if f.get('description')), '') \
        or (kev or {}).get('desc') or ''
    if not title:
        first = desc.split('. ')[0].strip()
        title = first[:140] + ('…' if len(first) > 140 else '')
    pub = [ts(f.get('published')) for f in base if f.get('published')]
    mod = [ts(f.get('modified')) for f in base if f.get('modified')]
    published = min([p for p in pub if p] or [ts((kev or {}).get('added')) or time.time()])
    modified = max([m for m in mod if m] or [published])
    cv = pick_cvss([x for f in base for x in f.get('cvss') or []])
    sev_label = next((f.get('severity_label') for f in osv if f.get('severity_label')), None)
    products = sorted({p for _, f in F for p in f.get('products') or []})
    refs, seen = [], set()
    for f in rich:
        for r in f.get('refs') or []:
            if r['url'] not in seen:
                seen.add(r['url'])
                refs.append(r)
    aff, seen = [], set()
    for f in vend + cve + osv:
        for a in f.get('affected') or []:
            k = (a.get('product'), a.get('package') or a.get('name'), tuple(a.get('ranges') or []))
            if k not in seen:
                seen.add(k)
                aff.append(a)
    aff.sort(key=lambda a: a.get('product') is None)
    v = {'id': vid, 'aliases': dumps([i for i in ids if i != vid]), 'state': state, 'title': title, 'description': desc,
         'published': published, 'modified': modified,
         'cvss_score': cv['score'] if cv else None, 'cvss_severity': (cv['severity'] if cv else sev_label) or None,
         'cvss_vector': cv.get('vector') if cv else None, 'cvss_version': cv.get('version') if cv else None,
         'cvss_source': cv.get('by') if cv else ('GHSA' if sev_label else None),
         'cwes': dumps(sorted({w for f in base for w in f.get('cwes') or []})), 'refs': dumps(refs[:40]), 'affected': dumps(aff[:40]),
         'products': dumps(products), 'kev': 1 if kev else 0, 'kev_added': ts(kev['added']) if kev else None,
         'kev_due': ts(kev['due']) if kev else None, 'kev_ransom': kev.get('ransom') if kev else None,
         'kev_action': kev.get('action') if kev else None,
         'epss': epss.get('epss') if epss else None, 'epss_pct': epss.get('percentile') if epss else None,
         'epss_date': epss.get('date') if epss else None}
    if v['cvss_severity'] and v['cvss_score'] is None and v['cvss_severity'] not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        v['cvss_severity'] = None
    v['priority'], v['priority_reason'] = priority(v)
    high_only = products and all(catalog.BY_SLUG[p].get('high_only') for p in products if p in catalog.BY_SLUG)
    relevant = bool(products) and state == 'PUBLISHED' and bool(cve or osv or kev)
    if relevant and high_only and not high_only_ok(v):
        relevant = False
    v['relevant'] = int(relevant)
    edge = time.time() - FEED_DAYS * 86400
    v['feed_ts'] = max(published, v['kev_added'] or 0)
    v['listed'] = int(relevant and v['feed_ts'] >= edge)
    old = c.execute('select * from vulns where id=?', (vid,)).fetchone()
    t = time.time()
    v['created'] = old['created'] if old else t
    v['updated'] = t
    cols = list(v)
    c.execute(f'insert or replace into vulns({",".join(cols)}) values({",".join("?" * len(cols))})', [v[k] for k in cols])
    c.execute('delete from vuln_products where vuln_id=?', (vid,))
    c.executemany('insert or ignore into vuln_products(vuln_id,product) values(?,?)', [(vid, p) for p in products])
    if relevant:
        events(c, old, v, aff)


def add_event(c, vid, typ, key, data, at):
    cur = c.execute('insert or ignore into events(vuln_id,type,key,data,ts) values(?,?,?,?,?)', (vid, typ, key, dumps(data), at))
    return cur.rowcount > 0


def events(c, old, v, aff):
    vid, now = v['id'], time.time()
    was = old and old['relevant']
    new_ev = []
    if add_event(c, vid, 'published', '', {'priority': v['priority']}, v['published']):
        new_ev.append(('published', v['published']))
    if v['cvss_score'] is not None and add_event(c, vid, 'scored', f"{v['cvss_source']}:{v['cvss_score']}",
                                                 {'score': v['cvss_score'], 'severity': v['cvss_severity'], 'by': v['cvss_source']},
                                                 now if was else v['published']):
        if was and old['cvss_score'] is not None:
            new_ev.append(('rescored', now))
        elif was:
            new_ev.append(('scored', now))
    if v['kev'] and add_event(c, vid, 'kev', '', {'added': v['kev_added'], 'due': v['kev_due'], 'ransom': v['kev_ransom']}, v['kev_added'] or now):
        new_ev.append(('kev', v['kev_added'] or now))
    for a in aff:
        for fx in a.get('fixed') or []:
            if a.get('product') and add_event(c, vid, 'fix', f"{a['product']}:{a.get('package') or ''}:{fx}",
                                              {'product': a['product'], 'package': a.get('package'), 'version': fx},
                                              now if was else v['published']):
                pass
    if v['epss'] and v['epss'] >= 0.1 and add_event(c, vid, 'epss_high', '', {'epss': v['epss']}, now if was else v['published']):
        new_ev.append(('epss_high', now))
    if v['listed']:
        from . import tg
        for typ, at in new_ev:
            if now - (at or 0) < ALERT_FRESH:
                tg.consider(c, v, typ, old)


def flush(c):
    n = 0
    while _dirty:
        vid = _dirty.pop()
        try:
            recompute(c, vid)
            n += 1
        except Exception:
            log.exception('recompute %s', vid)
    return n


def relist(c):
    """Окно ленты сдвигается со временем: пересчитать listed у всех релевантных."""
    edge = time.time() - FEED_DAYS * 86400
    c.execute('update vulns set listed = (relevant = 1 and feed_ts >= ?)', (edge,))
