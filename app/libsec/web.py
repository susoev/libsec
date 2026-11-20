"""Сайт: лента, страница уязвимости, продукты, статус источников, RSS и JSON API. Только чтение БД."""
import time
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape as xesc

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import catalog
from .db import DB, connect, loads

BASE = Path(__file__).resolve().parent.parent
SITE = 'https://websec.in'
PRIOS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED']
PAGE = 30

app = FastAPI(title='libsec', docs_url='/api/docs', redoc_url=None, openapi_url='/api/openapi.json')
app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')
tpl = Jinja2Templates(directory=BASE / 'templates')


_local = __import__('threading').local()


def db():
    """Одно read-only соединение на поток (uvicorn/anyio держит пул потоков)."""
    c = getattr(_local, 'c', None)
    if c is None:
        c = _local.c = connect(readonly=True)
    return c


def fmt_date(t, f='%Y-%m-%d'):
    return datetime.fromtimestamp(t, timezone.utc).strftime(f) if t else ''


def ago(t):
    if not t:
        return ''
    d = time.time() - t
    if d < 3600:
        return f'{max(1, int(d // 60))} min ago'
    if d < 86400:
        return f'{int(d // 3600)} h ago'
    if d < 86400 * 60:
        return f'{int(d // 86400)} d ago'
    return fmt_date(t)


tpl.env.filters.update(date=fmt_date, ago=ago, loads=lambda s: loads(s, []))
tpl.env.globals.update(catalog=catalog, CATS=catalog.CATS, SITE=SITE, PRIOS=PRIOS, year=lambda: datetime.now().year)


def analysis_map(c, ids):
    if not ids:
        return {}
    q = ','.join('?' * len(ids))
    return {r['vuln_id']: loads(r['data']) for r in c.execute(f'select vuln_id, data from analysis where data is not null and vuln_id in ({q})', ids)}


def query(c, product=None, prio=None, kev=False, q=None, listed=True, since=None, limit=PAGE, offset=0):
    where, args = [], []
    if listed:
        where.append('v.listed=1')
    else:
        where.append('v.relevant=1')
    if product:
        where.append('exists(select 1 from vuln_products p where p.vuln_id=v.id and p.product=?)')
        args.append(product)
    if prio:
        ps = [p for p in prio.upper().split(',') if p in PRIOS]
        if ps:
            where.append(f'v.priority in ({",".join("?" * len(ps))})')
            args += ps
    if kev:
        where.append('v.kev=1')
    if since:
        where.append('v.feed_ts>=?')
        args.append(since)
    if q:
        where.append('(v.id like ? or v.title like ? or v.description like ? or v.aliases like ?)')
        args += [f'%{q}%'] * 4
    sql = f'from vulns v where {" and ".join(where)}'
    total = c.execute(f'select count(*) {sql}', args).fetchone()[0]
    rows = c.execute(f'select v.* {sql} order by v.feed_ts desc limit ? offset ?', args + [limit, offset]).fetchall()
    return total, rows


def counts(c):
    r = {p: 0 for p in PRIOS}
    for row in c.execute('select priority, count(*) n from vulns where listed=1 group by priority'):
        r[row['priority']] = row['n']
    r['KEV'] = c.execute('select count(*) from vulns where listed=1 and kev=1').fetchone()[0]
    return r


@app.get('/health')
def health():
    c = db()
    n = c.execute('select count(*) from vulns where listed=1').fetchone()[0]
    last = c.execute('select max(last_ok) from sources').fetchone()[0]
    return {'ok': True, 'listed': n, 'last_collect': last}


@app.get('/', response_class=HTMLResponse)
def index(request: Request, product: str | None = None, prio: str | None = None, kev: int = 0, q: str | None = None, page: int = 1):
    c = db()
    page = max(1, page)
    total, rows = query(c, product, prio, bool(kev), q, offset=(page - 1) * PAGE)
    return tpl.TemplateResponse(request, 'index.html', {
        'rows': rows, 'ai': analysis_map(c, [r['id'] for r in rows]), 'total': total, 'page': page, 'pages': (total + PAGE - 1) // PAGE,
        'f': {'product': product, 'prio': prio, 'kev': kev, 'q': q}, 'counts': counts(c),
        'pc': {r[0]: r[1] for r in c.execute('select p.product, count(*) from vuln_products p join vulns v on v.id=p.vuln_id where v.listed=1 group by p.product')}})


@app.get('/vuln/{vid}', response_class=HTMLResponse)
def vuln(request: Request, vid: str):
    c = db()
    v = c.execute('select * from vulns where id=?', (vid,)).fetchone()
    if not v:
        a = c.execute('select vuln_id from aliases where alias=?', (vid,)).fetchone()
        if a and a[0] != vid:
            return Response(status_code=301, headers={'Location': f'/vuln/{a[0]}'})
        raise HTTPException(404)
    ev = c.execute('select * from events where vuln_id=? order by ts', (vid,)).fetchall()
    src = c.execute('select source, external_id, updated from facts where vuln_id=? order by source', (vid,)).fetchall()
    an = c.execute('select * from analysis where vuln_id=?', (vid,)).fetchone()
    return tpl.TemplateResponse(request, 'vuln.html', {'v': v, 'events': ev, 'sources': src,
                                                       'an': loads(an['data']) if an and an['data'] else None, 'an_row': an})


@app.get('/products', response_class=HTMLResponse)
def products(request: Request):
    c = db()
    st = {r['product']: r for r in c.execute(
        'select p.product, sum(v.listed) listed, count(*) total, sum(v.kev) kev, max(v.feed_ts) last from vuln_products p'
        ' join vulns v on v.id=p.vuln_id where v.relevant=1 group by p.product')}
    return tpl.TemplateResponse(request, 'products.html', {'st': st})


@app.get('/product/{slug}', response_class=HTMLResponse)
def product(request: Request, slug: str, page: int = 1):
    if slug not in catalog.BY_SLUG:
        raise HTTPException(404)
    c = db()
    page = max(1, page)
    total, rows = query(c, slug, listed=False, offset=(page - 1) * PAGE)
    return tpl.TemplateResponse(request, 'product.html', {'p': catalog.BY_SLUG[slug], 'rows': rows, 'ai': analysis_map(c, [r['id'] for r in rows]),
                                                          'total': total, 'page': page, 'pages': (total + PAGE - 1) // PAGE})


@app.get('/status', response_class=HTMLResponse)
def status(request: Request):
    c = db()
    src = c.execute('select * from sources order by name').fetchall()
    st = {
        'vulns': c.execute('select count(*) from vulns').fetchone()[0],
        'relevant': c.execute('select count(*) from vulns where relevant=1').fetchone()[0],
        'listed': c.execute('select count(*) from vulns where listed=1').fetchone()[0],
        'ai': c.execute('select count(*) from analysis where data is not null').fetchone()[0],
        'raw': {r[0]: r[1] for r in c.execute('select source, count(*) from raw_items group by source')},
        'tg': {r[0]: r[1] for r in c.execute('select status, count(*) from tg_queue group by status')},
    }
    return tpl.TemplateResponse(request, 'status.html', {'src': src, 'st': st, 'now': time.time()})


@app.get('/about', response_class=HTMLResponse)
def about(request: Request):
    return tpl.TemplateResponse(request, 'about.html', {})


# ---------- RSS
@app.get('/feed.xml')
def rss(product: str | None = None, prio: str | None = None, kev: int = 0):
    c = db()
    _, rows = query(c, product, prio, bool(kev), limit=50)
    ai = analysis_map(c, [r['id'] for r in rows])
    items = []
    for v in rows:
        a = ai.get(v['id']) or {}
        prods = ', '.join(catalog.BY_SLUG[p]['name'] for p in loads(v['products'], []) if p in catalog.BY_SLUG)
        title = f"[{v['priority']}] {v['id']}: {a.get('headline') or v['title']}"
        desc = a.get('summary') or (v['description'] or '')[:800]
        if a.get('action'):
            desc += '\n\nAction: ' + a['action']
        items.append(f"<item><title>{xesc(title)}</title><link>{SITE}/vuln/{v['id']}</link><guid isPermaLink=\"true\">{SITE}/vuln/{v['id']}</guid>"
                     f"<pubDate>{format_datetime(datetime.fromtimestamp(v['feed_ts'], timezone.utc))}</pubDate>"
                     f"<category>{xesc(prods)}</category><description>{xesc(desc)}</description></item>")
    name = 'libsec — web stack vulnerabilities' + (f' · {catalog.BY_SLUG[product]["name"]}' if product in catalog.BY_SLUG else '')
    body = ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>'
            f'<title>{xesc(name)}</title><link>{SITE}/</link><description>New vulnerabilities in PHP, Python, MySQL, nginx, Apache and other web-server software</description>'
            f'<atom:link href="{SITE}/feed.xml" rel="self" type="application/rss+xml"/><language>en</language>' + ''.join(items) + '</channel></rss>')
    return Response(body, media_type='application/rss+xml; charset=utf-8')


# ---------- JSON API
def vuln_json(c, v, a=None, full=False):
    d = {'id': v['id'], 'aliases': loads(v['aliases'], []), 'title': v['title'], 'url': f"{SITE}/vuln/{v['id']}",
         'products': loads(v['products'], []), 'priority': v['priority'], 'priority_reason': v['priority_reason'],
         'cvss': {'score': v['cvss_score'], 'severity': v['cvss_severity'], 'vector': v['cvss_vector'], 'version': v['cvss_version'],
                  'source': v['cvss_source']} if v['cvss_score'] is not None or v['cvss_severity'] else None,
         'kev': {'added': fmt_date(v['kev_added']), 'due': fmt_date(v['kev_due']), 'ransomware': v['kev_ransom']} if v['kev'] else None,
         'epss': {'score': v['epss'], 'percentile': v['epss_pct'], 'date': v['epss_date']} if v['epss'] is not None else None,
         'published': fmt_date(v['published'], '%Y-%m-%dT%H:%M:%SZ'), 'modified': fmt_date(v['modified'], '%Y-%m-%dT%H:%M:%SZ'),
         'ai': ({k: a[k] for k in a if not k.startswith('_')} if a else None)}
    if full:
        d.update(description=v['description'], cwes=loads(v['cwes'], []), affected=loads(v['affected'], []), references=loads(v['refs'], []),
                 events=[{'type': e['type'], 'ts': fmt_date(e['ts'], '%Y-%m-%dT%H:%M:%SZ'), 'data': loads(e['data'], {})}
                         for e in c.execute('select * from events where vuln_id=? order by ts', (v['id'],))])
    return d


@app.get('/api/v1/vulns')
def api_vulns(product: str | None = None, priority: str | None = None, kev: int = 0, q: str | None = None,
              since: str | None = Query(None, description='ISO date, by feed time'), all: int = Query(0, description='1 = beyond the 45-day feed window'),
              limit: int = Query(50, le=200), offset: int = 0):
    c = db()
    st = datetime.fromisoformat(since).replace(tzinfo=timezone.utc).timestamp() if since else None
    total, rows = query(c, product, priority, bool(kev), q, listed=not all, since=st, limit=limit, offset=offset)
    ai = analysis_map(c, [r['id'] for r in rows])
    return {'total': total, 'limit': limit, 'offset': offset, 'items': [vuln_json(c, v, ai.get(v['id'])) for v in rows],
            'license': 'Facts: CVE List (CVE terms of use), OSV/GitHub Advisory (CC-BY 4.0), CISA KEV and NVD (public domain), EPSS (FIRST.org). Summaries: libsec, AI-assisted.'}


@app.get('/api/v1/vulns/{vid}')
def api_vuln(vid: str):
    c = db()
    v = c.execute('select * from vulns where id=(select vuln_id from aliases where alias=?) or id=?', (vid, vid)).fetchone()
    if not v:
        raise HTTPException(404)
    return vuln_json(c, v, analysis_map(c, [v['id']]).get(v['id']), full=True)


@app.get('/api/v1/products')
def api_products():
    c = db()
    st = {r[0]: (r[1], r[2]) for r in c.execute('select p.product, sum(v.listed), count(*) from vuln_products p join vulns v on v.id=p.vuln_id where v.relevant=1 group by p.product')}
    return [{'slug': p['slug'], 'name': p['name'], 'category': catalog.CATS[p['cat']], 'feed_count': st.get(p['slug'], (0, 0))[0] or 0,
             'total': st.get(p['slug'], (0, 0))[1]} for p in catalog.P]


@app.get('/robots.txt', response_class=PlainTextResponse)
def robots():
    return 'User-agent: *\nDisallow: /\n'


@app.exception_handler(404)
def nf(request: Request, exc):
    if request.url.path.startswith('/api/'):
        return JSONResponse({'detail': 'not found'}, status_code=404)
    return tpl.TemplateResponse(request, 'base.html', {'notfound': True}, status_code=404)
