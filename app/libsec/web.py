"""Сайт: лента, страница уязвимости, продукты, статус источников, RSS, JSON API, sitemap. Только чтение БД.

Язык страницы — по поддомену (i18n.host_lang): websec.in — английский, es.websec.in и т.д. — переводы.
Ссылки в шаблонах относительные, поэтому пользователь остаётся на своём поддомене.
"""
import time
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape as xesc

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from . import catalog, i18n
from .i18n import LANGS, origin
from .db import DB, connect, loads

BASE = Path(__file__).resolve().parent.parent
SITE = origin(i18n.DEFAULT)
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


def clean(o):
    """JSON-LD без пустых значений."""
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items() if v not in (None, '', [])}
    if isinstance(o, list):
        return [clean(x) for x in o]
    return o


tpl.env.filters.update(clean=clean, date=fmt_date, loads=lambda s: loads(s, []),
                       ago=pass_context(lambda ctx, t: i18n.ago(t, ctx.get('L', i18n.DEFAULT))),
                       reason=pass_context(lambda ctx, s: i18n.reason(s, ctx.get('L', i18n.DEFAULT))))
tpl.env.globals.update(refs_urls=lambda refs, n: [r['url'] for r in loads(refs, [])[:n] if r.get('url')],
                       soft=lambda ps: [{'@type': 'SoftwareApplication', 'name': catalog.BY_SLUG[p]['name']} for p in ps if p in catalog.BY_SLUG],
                       catalog=catalog, CATS=catalog.CATS, SITE=SITE, PRIOS=PRIOS, LANGS=LANGS, BRAND=i18n.BRAND, GITHUB=i18n.GITHUB,
                       year=lambda: datetime.now().year)


def lang_of(request):
    return i18n.host_lang(request.headers.get('host'))


def render(request, name, ctx, *, path=None, langs=None, index=True, status=200, ld=None):
    """Шаблон + SEO-обвязка: язык, canonical, hreflang (только языки, где страница есть и индексируется), robots.
    path — канонический путь с нужными параметрами (по умолчанию путь запроса без параметров)."""
    L = lang_of(request)
    path = path or request.url.path
    langs = [l for l in LANGS if langs is None or l in langs]
    index = index and L in langs
    alts = [(LANGS[l]['hreflang'], origin(l) + path) for l in langs] if index and len(langs) > 1 else []
    if alts and i18n.DEFAULT in langs:
        alts.append(('x-default', origin(i18n.DEFAULT) + path))
    ctx.update(L=L, _=i18n.gettext(L), ld=ld or [], ORIGIN=origin(L), canonical=origin(L) + path, alts=alts, path=path,
               robots='index,follow' if index else 'noindex,follow', page_langs=langs,
               switch=[(l, LANGS[l]['name'], origin(l) + path) for l in LANGS])
    return tpl.TemplateResponse(request, name, ctx, status_code=status)


# ---------- schema.org (JSON-LD): общие куски
def ld_org():
    return {'@type': 'Organization', '@id': SITE + '/#org', 'name': i18n.BRAND, 'url': SITE + '/', 'sameAs': [i18n.GITHUB]}


def ld_dataset(L):
    _ = i18n.gettext(L)
    o = origin(L)
    return {'@context': 'https://schema.org', '@type': 'Dataset', '@id': SITE + '/#dataset', 'name': f'{i18n.BRAND} — ' + str(_('web stack vulnerabilities')),
            'description': str(_('Fresh vulnerabilities in PHP, Python, MySQL, nginx, Apache and other web-server software, deduplicated across CVE, OSV, GitHub Advisory, CISA KEV and EPSS.')),
            'url': o + '/', 'inLanguage': LANGS[L]['hreflang'], 'isAccessibleForFree': True, 'creator': ld_org(), 'publisher': ld_org(),
            'keywords': ['CVE', 'vulnerability', 'security advisory', 'CVSS', 'EPSS', 'CISA KEV', 'PHP', 'nginx', 'Apache', 'MySQL', 'Python'],
            'license': 'https://www.cve.org/Legal/TermsOfUse', 'isBasedOn': ['https://www.cve.org/', 'https://osv.dev/', 'https://github.com/advisories',
                                                                             'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'https://www.first.org/epss/'],
            'distribution': [{'@type': 'DataDownload', 'encodingFormat': 'application/rss+xml', 'contentUrl': o + '/feed.xml'},
                             {'@type': 'DataDownload', 'encodingFormat': 'application/json', 'contentUrl': SITE + '/api/v1/vulns'}],
            'measurementTechnique': 'CVSS, EPSS, CISA KEV', 'temporalCoverage': '2020/..'}


def ld_source_code():
    return {'@context': 'https://schema.org', '@type': 'SoftwareSourceCode', 'name': 'libsec', 'codeRepository': i18n.GITHUB,
            'programmingLanguage': 'Python', 'runtimePlatform': 'Python 3', 'author': ld_org(),
            'description': 'Collectors, deduplication, priority rule, AI summaries, site, RSS and JSON API of ' + i18n.BRAND}


def ld_list(L, rows, ai, name, url, about=None):
    """CollectionPage + ItemList карточек на странице."""
    o = origin(L)
    d = {'@context': 'https://schema.org', '@type': 'CollectionPage', 'name': name, 'url': url, 'inLanguage': LANGS[L]['hreflang'],
         'isPartOf': {'@type': 'WebSite', 'name': i18n.BRAND, 'url': o + '/'},
         'mainEntity': {'@type': 'ItemList', 'numberOfItems': len(rows), 'itemListElement': [
             {'@type': 'ListItem', 'position': i + 1, 'url': f"{o}/vuln/{v['id']}",
              'name': f"{v['id']}: {(ai.get(v['id']) or {}).get('headline') or v['title'] or ''}"[:150]} for i, v in enumerate(rows)]}}
    if about:
        d['about'] = about
    return d


def tr_rows(c, ids, lang):
    """{vuln_id: перевод} — только актуальные (хэш совпадает с текущим английским разбором)."""
    if lang == i18n.DEFAULT or not ids:
        return {}
    q = ','.join('?' * len(ids))
    return {r[0]: (r[1], loads(r[2])) for r in c.execute(
        f'select vuln_id, input_hash, data from analysis_tr where lang=? and data is not null and vuln_id in ({q})', [lang] + list(ids))}


def analysis_map(c, ids, lang=i18n.DEFAULT):
    if not ids:
        return {}
    q = ','.join('?' * len(ids))
    out = {r['vuln_id']: loads(r['data']) for r in c.execute(f'select vuln_id, data from analysis where data is not null and vuln_id in ({q})', ids)}
    for vid, (ih, d) in tr_rows(c, list(out), lang).items():
        if d and ih == i18n.tr_hash(out[vid]):
            out[vid] = {**out[vid], **d, '_tr': True}
    return out


def tr_langs(c, vid, an):
    """Языки, на которых у записи есть полная страница (английский + актуальные переводы разбора)."""
    if not an:
        return [i18n.DEFAULT]
    ih = i18n.tr_hash(an)
    return [i18n.DEFAULT] + [r[0] for r in c.execute('select lang from analysis_tr where vuln_id=? and input_hash=? and data is not null', (vid, ih))]


def query(c, product=None, prio=None, kev=False, q=None, listed=True, since=None, limit=PAGE, offset=0):
    where, args = [], []
    if listed:
        where.append('v.listed=1')
    else:
        where.append('v.relevant=1')
    if product:
        ps = [x.strip().lower() for x in product.split(',') if x.strip()] or ['']
        where.append(f'exists(select 1 from vuln_products p where p.vuln_id=v.id and p.product in ({",".join("?" * len(ps))}))')
        args += ps
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
    filtered = bool(product or prio or kev or q)
    L = lang_of(request)
    ai = analysis_map(c, [r['id'] for r in rows], L)
    ld_index = [ld_list(L, rows, ai, f"{i18n.BRAND} — {i18n.gettext(L)('web stack vulnerability feed')}", origin(L) + '/')] + ([ld_dataset(L)] if page == 1 else [])
    return render(request, 'index.html', {
        'rows': rows, 'ai': ai, 'total': total, 'page': page, 'pages': (total + PAGE - 1) // PAGE,
        'f': {'product': product, 'prio': prio, 'kev': kev, 'q': q}, 'counts': counts(c),
        'pc': {r[0]: r[1] for r in c.execute('select p.product, count(*) from vuln_products p join vulns v on v.id=p.vuln_id where v.listed=1 group by p.product')}},
        path='/' + (f'?page={page}' if page > 1 else ''), index=not filtered, ld=ld_index)


@app.get('/vuln/{vid}', response_class=HTMLResponse)
def vuln(request: Request, vid: str):
    c = db()
    v = c.execute('select * from vulns where id=?', (vid,)).fetchone()
    if not v:
        a = c.execute('select vuln_id from aliases where alias=?', (vid,)).fetchone()
        if a and a[0] != vid:
            return Response(status_code=301, headers={'Location': f'/vuln/{a[0]}'})
        raise HTTPException(404)
    L = lang_of(request)
    ev = c.execute('select * from events where vuln_id=? order by ts', (vid,)).fetchall()
    src = c.execute('select source, external_id, updated from facts where vuln_id=? order by source', (vid,)).fetchall()
    an_row = c.execute('select * from analysis where vuln_id=?', (vid,)).fetchone()
    an_en = loads(an_row['data']) if an_row and an_row['data'] else None
    an = analysis_map(c, [vid], L).get(vid) if an_en else None
    prods = [p for p in loads(v['products'], []) if p in catalog.BY_SLUG]
    related = []
    for p in prods[:2]:
        rr = c.execute('select v.id, v.title, v.priority, v.feed_ts from vuln_products p join vulns v on v.id=p.vuln_id'
                       ' where p.product=? and v.relevant=1 and v.id<>? order by v.feed_ts desc limit 6', (p, vid)).fetchall()
        if rr:
            ra = analysis_map(c, [r['id'] for r in rr], L)
            related.append((catalog.BY_SLUG[p], [(r, ra.get(r['id'])) for r in rr]))
    return render(request, 'vuln.html', {'v': v, 'events': ev, 'sources': src, 'an': an, 'an_row': an_row, 'prods': prods, 'related': related,
                                         'head': (an or {}).get('headline') or v['title'] or vid},
                  path=f'/vuln/{vid}', langs=tr_langs(c, vid, an_en), index=bool(v['relevant']))


@app.get('/products', response_class=HTMLResponse)
def products(request: Request):
    c = db()
    st = {r['product']: r for r in c.execute(
        'select p.product, sum(v.listed) listed, count(*) total, sum(v.kev) kev, max(v.feed_ts) last from vuln_products p'
        ' join vulns v on v.id=p.vuln_id where v.relevant=1 group by p.product')}
    L = lang_of(request)
    ld = [{'@context': 'https://schema.org', '@type': 'CollectionPage', 'name': str(i18n.gettext(L)('Tracked products')), 'url': origin(L) + '/products',
           'inLanguage': LANGS[L]['hreflang'], 'mainEntity': {'@type': 'ItemList', 'numberOfItems': len(catalog.P), 'itemListElement': [
               {'@type': 'ListItem', 'position': i + 1, 'url': f"{origin(L)}/product/{p['slug']}", 'name': p['name']} for i, p in enumerate(catalog.P)]}}]
    return render(request, 'products.html', {'st': st}, ld=ld)


@app.get('/product/{slug}', response_class=HTMLResponse)
def product(request: Request, slug: str, page: int = 1):
    if slug not in catalog.BY_SLUG:
        raise HTTPException(404)
    c = db()
    page = max(1, page)
    total, rows = query(c, slug, listed=False, offset=(page - 1) * PAGE)
    p = catalog.BY_SLUG[slug]
    L = lang_of(request)
    ai = analysis_map(c, [r['id'] for r in rows], L)
    ld = [ld_list(L, rows, ai, str(i18n.gettext(L)('{name} vulnerabilities', name=p['name'])), f'{origin(L)}/product/{slug}',
                  about={'@type': 'SoftwareApplication', 'name': p['name'], 'applicationCategory': catalog.CATS[p['cat']]})]
    return render(request, 'product.html', {'p': p, 'rows': rows, 'ai': ai,
                                            'total': total, 'page': page, 'pages': (total + PAGE - 1) // PAGE,
                                            'siblings': [x for x in catalog.P if x['cat'] == p['cat'] and x['slug'] != slug]},
                  path=f'/product/{slug}' + (f'?page={page}' if page > 1 else ''), ld=ld)


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
    return render(request, 'status.html', {'src': src, 'st': st, 'now': time.time()}, index=False)


@app.get('/about', response_class=HTMLResponse)
def about(request: Request):
    L = lang_of(request)
    ld = [{'@context': 'https://schema.org', '@type': 'AboutPage', 'url': origin(L) + '/about', 'inLanguage': LANGS[L]['hreflang'],
           'name': str(i18n.gettext(L)('About {b}', b=i18n.BRAND)), 'about': ld_org()}, ld_dataset(L), ld_source_code()]
    return render(request, 'about.html', {}, ld=ld)


# ---------- RSS
@app.get('/feed.xml')
def rss(request: Request, product: str | None = None, prio: str | None = None, kev: int = 0):
    c = db()
    L = lang_of(request)
    _ = i18n.gettext(L)
    site = origin(L)
    _n, rows = query(c, product, prio, bool(kev), limit=50)
    ai = analysis_map(c, [r['id'] for r in rows], L)
    items = []
    for v in rows:
        a = ai.get(v['id']) or {}
        prods = ', '.join(catalog.BY_SLUG[p]['name'] for p in loads(v['products'], []) if p in catalog.BY_SLUG)
        title = f"[{v['priority']}] {v['id']}: {a.get('headline') or v['title']}"
        desc = a.get('summary') or (v['description'] or '')[:800]
        if a.get('action'):
            desc += '\n\n' + str(_('What to do:')) + ' ' + a['action']
        items.append(f"<item><title>{xesc(title)}</title><link>{site}/vuln/{v['id']}</link><guid isPermaLink=\"true\">{site}/vuln/{v['id']}</guid>"
                     f"<pubDate>{format_datetime(datetime.fromtimestamp(v['feed_ts'], timezone.utc))}</pubDate>"
                     f"<category>{xesc(prods)}</category><description>{xesc(desc)}</description></item>")
    name = f'{i18n.BRAND} — ' + str(_('web stack vulnerabilities')) + (f' · {catalog.BY_SLUG[product]["name"]}' if product in catalog.BY_SLUG else '')
    body = ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>'
            f'<title>{xesc(name)}</title><link>{site}/</link><description>{xesc(str(_("New vulnerabilities in PHP, Python, MySQL, nginx, Apache and other web-server software")))}</description>'
            f'<atom:link href="{site}/feed.xml" rel="self" type="application/rss+xml"/><language>{LANGS[L]["hreflang"]}</language>' + ''.join(items) + '</channel></rss>')
    return Response(body, media_type='application/rss+xml; charset=utf-8')


# ---------- JSON API (только websec.in, только английский; см. /api/doc)
API_DOC = SITE + '/api/doc'
API_ABOUT = ('WebSec (websec.in): vulnerabilities in PHP, Python, MySQL, nginx, Apache and 45 more web-server products, '
             'merged from CVE, OSV/GitHub Advisory, CISA KEV and EPSS, ranked by urgency, with AI summaries and fix versions. '
             'Read-only, no key. How to use: see "doc".')
LICENSE = ('Facts: CVE List (CVE terms of use), OSV/GitHub Advisory (CC-BY 4.0), CISA KEV and NVD (public domain), '
           'EPSS (FIRST.org). Summaries: WebSec, AI-assisted, may contain errors; sources are authoritative.')
TS = '%Y-%m-%dT%H:%M:%SZ'


def api_ok(**kw):
    """Конверт любого ответа API: result, doc, about — сверху, данные — дальше."""
    return {'result': True, 'doc': API_DOC, 'about': API_ABOUT, 'generated': fmt_date(time.time(), TS), **kw}


def api_err(status, error):
    return JSONResponse({'result': False, 'doc': API_DOC, 'about': API_ABOUT, 'error': error}, status_code=status)


def fixed_versions(v, a):
    """Версии с исправлением: проверенные в коде из ИИ-разбора, иначе — из диапазонов источников."""
    if a and a.get('fixed_versions'):
        return a['fixed_versions']
    out = []
    for af in loads(v['affected'], []):
        out += [f for f in af.get('fixed') or [] if f not in out]
    return out


def vuln_json(c, v, a=None, full=False, events=True):
    d = {'id': v['id'], 'aliases': loads(v['aliases'], []), 'title': v['title'], 'headline': (a or {}).get('headline'),
         'url': f"{SITE}/vuln/{v['id']}", 'api': f"{SITE}/api/v1/vulns/{v['id']}",
         'products': loads(v['products'], []), 'priority': v['priority'], 'priority_reason': v['priority_reason'],
         'exploited': bool(v['kev']),
         'cvss': {'score': v['cvss_score'], 'severity': v['cvss_severity'], 'vector': v['cvss_vector'], 'version': v['cvss_version'],
                  'source': v['cvss_source']} if v['cvss_score'] is not None or v['cvss_severity'] else None,
         'kev': {'added': fmt_date(v['kev_added']), 'due': fmt_date(v['kev_due']), 'ransomware': v['kev_ransom']} if v['kev'] else None,
         'epss': {'score': v['epss'], 'percentile': v['epss_pct'], 'date': v['epss_date']} if v['epss'] is not None else None,
         'published': fmt_date(v['published'], TS), 'modified': fmt_date(v['modified'], TS), 'feed_at': fmt_date(v['feed_ts'], TS),
         'fixed_versions': fixed_versions(v, a), 'action': (a or {}).get('action'),
         'ai': ({k: a[k] for k in a if not k.startswith('_')} if a else None)}
    if full:
        d.update(description=v['description'], cwes=loads(v['cwes'], []), affected=loads(v['affected'], []), references=loads(v['refs'], []))
        if events:
            d['events'] = [{'type': e['type'], 'ts': fmt_date(e['ts'], TS), 'data': loads(e['data'], {})}
                           for e in c.execute('select * from events where vuln_id=? order by ts', (v['id'],))]
    return d


def since_ts(since):
    try:
        return datetime.fromisoformat(since).replace(tzinfo=timezone.utc).timestamp() if since else None
    except ValueError:
        raise HTTPException(400, 'since: expected ISO date, e.g. 2026-11-01 or 2026-11-01T12:00:00')


API_ENDPOINTS = {
    'GET /api/high10': 'The 10 newest CRITICAL and HIGH vulnerabilities, full detail (what to fix and how). '
                       'Params: product=php,nginx  priority=CRITICAL  kev=1  n=1..50',
    'GET /api/v1/vulns': 'The feed, newest first. Params: product, priority=CRITICAL,HIGH, kev=1, q, since=2026-11-01, all=1, limit<=200, offset',
    'GET /api/v1/vulns/{id}': 'One record by CVE id or any alias (GHSA, PYSEC...): affected versions, references, timeline',
    'GET /api/v1/products': 'The product catalog: slugs for the product= parameter',
    'GET /api/doc': 'How to use this API (Markdown)',
    'GET /api/openapi.json': 'OpenAPI schema; interactive: /api/docs',
}


@app.middleware('http')
async def api_guard(request: Request, call_next):
    """API только на главном домене: с языковых поддоменов — 301 на websec.in. Ответы API открыты для CORS."""
    p = request.url.path
    if p != '/api' and not p.startswith('/api/'):
        return await call_next(request)
    if lang_of(request) != i18n.DEFAULT:
        return RedirectResponse(SITE + p + (f'?{request.url.query}' if request.url.query else ''), 301)
    r = await call_next(request)
    r.headers.setdefault('Access-Control-Allow-Origin', '*')
    r.headers.setdefault('Cache-Control', 'public, max-age=60')
    return r


@app.get('/api')
def api_index():
    return api_ok(endpoints=[{'endpoint': k, 'url': SITE + k.split(' ', 1)[1], 'what': v} for k, v in API_ENDPOINTS.items()],
                  quick_start=f'curl -s {SITE}/api/high10', license=LICENSE)


@app.get('/api/high10')
def api_high10(product: str | None = Query(None, description='Comma-separated product slugs, see /api/v1/products'),
               priority: str = Query('CRITICAL,HIGH', description='CRITICAL, HIGH or both'),
               kev: int = Query(0, description='1 = only exploited in the wild (CISA KEV)'),
               n: int = Query(10, ge=1, le=50, description='How many records')):
    """Последние N критичных/высоких — для агента, который по расписанию чинит серверы."""
    c = db()
    total, rows = query(c, product, priority, bool(kev), listed=False, limit=n)
    ai = analysis_map(c, [r['id'] for r in rows])
    items = [vuln_json(c, v, ai.get(v['id']), full=True, events=False) for v in rows]
    return api_ok(count=len(items), total=total, filter={'priority': priority.upper(), 'product': product, 'kev': bool(kev)},
                  latest_feed_at=items[0]['feed_at'] if items else None, items=items, license=LICENSE)


@app.get('/api/v1/vulns')
def api_vulns(product: str | None = None, priority: str | None = None, kev: int = 0, q: str | None = None,
              since: str | None = Query(None, description='ISO date, by feed time'), all: int = Query(0, description='1 = beyond the 45-day feed window'),
              limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    c = db()
    total, rows = query(c, product, priority, bool(kev), q, listed=not all, since=since_ts(since), limit=limit, offset=offset)
    ai = analysis_map(c, [r['id'] for r in rows])
    return api_ok(total=total, limit=limit, offset=offset, items=[vuln_json(c, v, ai.get(v['id'])) for v in rows], license=LICENSE)


@app.get('/api/v1/vulns/{vid}')
def api_vuln(vid: str):
    c = db()
    v = c.execute('select * from vulns where id=(select vuln_id from aliases where alias=?) or id=?', (vid, vid)).fetchone()
    if not v:
        raise HTTPException(404, f'{vid}: no such record')
    return api_ok(item=vuln_json(c, v, analysis_map(c, [v['id']]).get(v['id']), full=True), license=LICENSE)


@app.get('/api/v1/products')
def api_products():
    c = db()
    st = {r[0]: (r[1], r[2]) for r in c.execute('select p.product, sum(v.listed), count(*) from vuln_products p join vulns v on v.id=p.vuln_id where v.relevant=1 group by p.product')}
    return api_ok(items=[{'slug': p['slug'], 'name': p['name'], 'category': catalog.CATS[p['cat']], 'feed_count': st.get(p['slug'], (0, 0))[0] or 0,
                          'total': st.get(p['slug'], (0, 0))[1]} for p in catalog.P])


@app.get('/api/doc', response_class=PlainTextResponse)
def api_doc():
    return PlainTextResponse((BASE.parent / 'docs' / 'api.md').read_text(), media_type='text/plain; charset=utf-8')


@app.exception_handler(RequestValidationError)
def bad_params(request: Request, exc):
    return api_err(400, '; '.join(f"{'.'.join(str(x) for x in e['loc'][1:])}: {e['msg']}" for e in exc.errors()))


@app.get('/robots.txt', response_class=PlainTextResponse)
def robots(request: Request):
    return f'User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: {origin(lang_of(request))}/sitemap.xml\n'


def md(s):
    return ' '.join(str(s or '').split())


@app.get('/llms.txt', response_class=PlainTextResponse)
def llms(request: Request):
    """llms.txt (llmstxt.org): что это за сайт и где машиночитаемые данные. Ссылки — на поддомен запроса."""
    L = lang_of(request)
    o = origin(L)
    _ = i18n.gettext(L)
    c = db()
    top = c.execute("select id, title from vulns where listed=1 and (kev=1 or priority='CRITICAL') order by feed_ts desc limit 15").fetchall()
    ai = analysis_map(c, [r['id'] for r in top], L)
    out = [f'# {i18n.BRAND}', '',
           f"> {md(_('Fresh vulnerabilities in PHP, Python, MySQL, nginx, Apache and other web-server software, deduplicated across CVE, OSV, GitHub Advisory, CISA KEV and EPSS.'))}", '',
           'A vulnerability tracker for the web stack (50 products: languages, web servers, databases, crypto, containers, frameworks, CMS). '
           'Facts come from CVE List V5, OSV/GitHub Advisory, CISA KEV, EPSS and vendor advisories; duplicates are merged into one record with aliases. '
           'Priority is a transparent rule over vendor/CNA CVSS, KEV and EPSS. AI summaries are generated only from collected facts, '
           'fixed versions are verified in code, and AI text is labelled. CVSS is never invented. No exploit code is published.', '',
           f'Languages: English at {origin(i18n.DEFAULT)}/, translations at ' + ', '.join(f'{origin(l)}/ ({LANGS[l]["name"]})' for l in i18n.TR_LANGS) + '. '
           'AI summaries are machine-translated from English; original CVE descriptions stay in English.', '',
           '## Data access', '',
           f'- [API guide]({SITE}/api/doc): JSON API, English, main domain only; every response starts with `result` and `doc`',
           f'- [JSON API: what to fix now]({SITE}/api/high10): the 10 newest CRITICAL/HIGH records with fixed versions and actions, `?product=php,nginx&priority=CRITICAL&kev=1&n=20`',
           f'- [JSON API: feed]({SITE}/api/v1/vulns): `?product=nginx&priority=CRITICAL,HIGH&kev=1&since=2026-11-01&limit=50`, `all=1` for history beyond 45 days',
           f'- [JSON API: one record]({SITE}/api/v1/vulns/CVE-2024-4577): affected versions, references, timeline; any alias (GHSA, PYSEC…) works',
           f'- [JSON API: products]({SITE}/api/v1/products): the catalog',
           f'- [OpenAPI]({SITE}/api/openapi.json): schema, [docs]({SITE}/api/docs)',
           f'- [RSS]({o}/feed.xml): `?product=php&prio=CRITICAL,HIGH&kev=1`',
           f'- [Full feed as text]({o}/llms-full.txt): the current 45-day feed with summaries, actions and fixed versions',
           f'- [Sitemap]({o}/sitemap.xml)', '',
           '## Pages', '',
           f'- [Feed]({o}/): new and escalated vulnerabilities, last 45 days, filters by priority, KEV, product, search `?q=`',
           f'- [Products]({o}/products): tracked products by category',
           f'- [About, method and API]({o}/about): sources, licences, priority rule, caveats',
           f'- [Collector status]({o}/status): freshness of every source', '',
           '## Products', '']
    out += [f'- [{p["name"]}]({o}/product/{p["slug"]}): {catalog.CATS[p["cat"]]}' for p in catalog.P]
    out += ['', '## Latest critical or exploited', '']
    out += [f'- [{r["id"]}]({o}/vuln/{r["id"]}): {md((ai.get(r["id"]) or {}).get("headline") or r["title"])}' for r in top]
    out += ['', '## Optional', '',
            f'- [Source code]({i18n.GITHUB}): collectors, site and API (Python, FastAPI, SQLite)',
            '- Licences: CVE List — CVE Terms of Use; OSV/GitHub Advisory — CC-BY 4.0; CISA KEV and NVD — public domain; EPSS — FIRST.org, free use with attribution.', '']
    return PlainTextResponse('\n'.join(out), media_type='text/markdown; charset=utf-8')


@app.get('/llms-full.txt', response_class=PlainTextResponse)
def llms_full(request: Request):
    """Текущая лента (45 дней) в Markdown: для LLM-агентов, без HTML."""
    L = lang_of(request)
    o = origin(L)
    c = db()
    rows = c.execute('select * from vulns where listed=1 order by feed_ts desc limit 500').fetchall()
    ai = analysis_map(c, [r['id'] for r in rows], L)
    out = [f'# {i18n.BRAND} — web stack vulnerabilities, last 45 days', '',
           f'> {len(rows)} records, newest first. Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC. '
           f'Machine-readable: {SITE}/api/v1/vulns. Sources are authoritative; AI text can be wrong.', '']
    for v in rows:
        a = ai.get(v['id']) or {}
        prods = ', '.join(catalog.BY_SLUG[p]['name'] for p in loads(v['products'], []) if p in catalog.BY_SLUG)
        out.append(f"## {v['id']}: {md(a.get('headline') or v['title'])}")
        out.append('')
        meta = [f"Priority: {v['priority'].lower()} ({v['priority_reason']})", f'Products: {prods}']
        if v['cvss_score'] is not None:
            meta.append(f"CVSS {v['cvss_score']} ({v['cvss_source']})")
        if v['epss'] is not None:
            meta.append(f"EPSS {v['epss'] * 100:.1f}%")
        if v['kev']:
            meta.append(f"CISA KEV since {fmt_date(v['kev_added'])}")
        aliases = loads(v['aliases'], [])
        if aliases:
            meta.append('Aliases: ' + ', '.join(aliases))
        meta.append(f"Published {fmt_date(v['published'])}, URL {o}/vuln/{v['id']}")
        out += [f'- {m}' for m in meta] + ['']
        if a.get('summary'):
            out.append(md(a['summary']) + ' (AI)')
            if a.get('action'):
                out.append('Action: ' + md(a['action']))
            if a.get('fixed_versions'):
                out.append('Fixed versions (verified against sources): ' + ', '.join(a['fixed_versions']))
        else:
            out.append(md(v['description'])[:1200])
        out.append('')
    return PlainTextResponse('\n'.join(out), media_type='text/markdown; charset=utf-8')


@app.get('/sitemap.xml')
def sitemap(request: Request):
    """Sitemap своего поддомена с xhtml:link на все языковые версии каждой страницы."""
    L = lang_of(request)
    c = db()
    pages = [('/', None, LANGS), ('/products', None, LANGS), ('/about', None, LANGS)]
    last = {r[0]: r[1] for r in c.execute('select p.product, max(v.modified) from vuln_products p join vulns v on v.id=p.vuln_id where v.relevant=1 group by p.product')}
    pages += [(f'/product/{p["slug"]}', last.get(p['slug']), LANGS) for p in catalog.P]
    an = {r[0]: i18n.tr_hash(loads(r[1])) for r in c.execute('select vuln_id, data from analysis where data is not null')}
    tr = {}
    for vid, lang, ih in c.execute('select vuln_id, lang, input_hash from analysis_tr where data is not null'):
        if an.get(vid) == ih:
            tr.setdefault(vid, []).append(lang)
    for vid, mod in c.execute('select id, modified from vulns where relevant=1 order by feed_ts desc'):
        langs = [i18n.DEFAULT] + tr.get(vid, [])
        if L in langs:
            pages.append((f'/vuln/{vid}', mod, langs))
    out = ['<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">']
    for path, mod, langs in pages:
        out.append(f'<url><loc>{xesc(origin(L) + path)}</loc>' + (f'<lastmod>{fmt_date(mod)}</lastmod>' if mod else ''))
        if len(langs) > 1:
            out += [f'<xhtml:link rel="alternate" hreflang="{LANGS[l]["hreflang"]}" href="{xesc(origin(l) + path)}"/>' for l in LANGS if l in langs]
            out.append(f'<xhtml:link rel="alternate" hreflang="x-default" href="{xesc(origin(i18n.DEFAULT) + path)}"/>')
        out.append('</url>')
    out.append('</urlset>')
    return Response('\n'.join(out), media_type='application/xml; charset=utf-8')


@app.exception_handler(StarletteHTTPException)
def http_err(request: Request, exc):
    p = request.url.path
    if p == '/api' or p.startswith('/api/'):
        return api_err(exc.status_code, exc.detail if exc.status_code != 404 or exc.detail != 'Not Found' else 'no such endpoint, see /api')
    if exc.status_code != 404:
        return JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
    return render(request, 'base.html', {'notfound': True}, index=False, status=404)
