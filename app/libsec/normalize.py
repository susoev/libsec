"""Разбор записей источников в единый формат «фактов» и привязка к каталогу.

facts = {
  ids: [все идентификаторы], primary: CVE-… | None, state, title, description, published, modified (ISO),
  cvss: [{score, severity, vector, version, by}], severity_label, cwes, refs: [{url, tags, by}],
  affected: [{product, vendor, name, ecosystem, ranges: [str], fixed: [str]}], products: [slug], kev: {...}
}
"""
import math, re
from . import catalog

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def band(score):
    if score is None:
        return None
    if score >= 9:
        return 'CRITICAL'
    if score >= 7:
        return 'HIGH'
    if score >= 4:
        return 'MEDIUM'
    if score > 0:
        return 'LOW'
    return 'NONE'


# ---------- CVSS 3.x: базовая оценка из вектора (для OSV, где только вектор)
_W = {'AV': {'N': .85, 'A': .62, 'L': .55, 'P': .2}, 'AC': {'L': .77, 'H': .44}, 'UI': {'N': .85, 'R': .62},
      'C': {'H': .56, 'L': .22, 'N': 0}, 'I': {'H': .56, 'L': .22, 'N': 0}, 'A': {'H': .56, 'L': .22, 'N': 0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(':') for p in vector.split('/')[1:])
        s = m['S']
        pr = {'N': .85, 'L': .68 if s == 'C' else .62, 'H': .5 if s == 'C' else .27}[m['PR']]
        iss = 1 - (1 - _W['C'][m['C']]) * (1 - _W['I'][m['I']]) * (1 - _W['A'][m['A']])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if s == 'C' else 6.42 * iss
        ex = 8.22 * _W['AV'][m['AV']] * _W['AC'][m['AC']] * pr * _W['UI'][m['UI']]
        if imp <= 0:
            return 0.0
        return _roundup(min(1.08 * (imp + ex), 10)) if s == 'C' else _roundup(min(imp + ex, 10))
    except (KeyError, ValueError, IndexError):
        return None


# ---------- версии
def _cve_ranges(a):
    """affected[] из CVE 5.x -> (ranges, fixed) человекочитаемо."""
    ranges, fixed = [], []
    for v in a.get('versions') or []:
        ver, st = (v.get('version') or '').strip(), v.get('status')
        lt, le = v.get('lessThan'), v.get('lessThanOrEqual')
        if st == 'affected':
            if lt or le:
                lo = '' if ver in ('', '0', '*', 'n/a') else f'>= {ver}, '
                ranges.append(f'{lo}< {lt}' if lt and lt != '*' else (f'{lo}<= {le}' if le and le != '*' else f'>= {ver}'))
                if lt and lt != '*':
                    fixed.append(lt)
            elif ver and ver not in ('n/a', '*'):
                ranges.append(ver)
            for ch in v.get('changes') or []:
                if ch.get('status') == 'unaffected' and ch.get('at'):
                    fixed.append(ch['at'])
        elif st == 'unaffected' and ver and ver not in ('0', '*', 'n/a') and not lt:
            fixed.append(ver if not le else f'> {le}')
    return ranges[:12], list(dict.fromkeys(fixed))[:12]


def _osv_ranges(a):
    ranges, fixed = [], []
    for r in a.get('ranges') or []:
        if r.get('type') == 'GIT':
            continue
        intro = None
        for e in r.get('events') or []:
            if 'introduced' in e:
                intro = e['introduced']
            elif 'fixed' in e:
                ranges.append((f'>= {intro}, ' if intro not in (None, '0') else '') + f'< {e["fixed"]}')
                fixed.append(e['fixed'])
                intro = None
            elif 'last_affected' in e:
                ranges.append((f'>= {intro}, ' if intro not in (None, '0') else '') + f'<= {e["last_affected"]}')
                intro = None
        if intro is not None:
            ranges.append(f'>= {intro}' if intro != '0' else 'all versions')
    if not ranges and a.get('versions'):
        vs = a['versions']
        ranges.append(', '.join(vs[:6]) + (f' … (+{len(vs) - 6})' if len(vs) > 6 else ''))
    return ranges[:12], list(dict.fromkeys(fixed))[:12]


# ---------- CVE 5.x (cvelistV5 / CVE Services)
def parse_cve(rec):
    md = rec.get('cveMetadata', {})
    cid = md.get('cveId')
    cna = rec.get('containers', {}).get('cna', {})
    conts = [('cna', cna)] + [(c.get('providerMetadata', {}).get('shortName', 'adp'), c) for c in rec.get('containers', {}).get('adp', [])]
    f = {'ids': [cid], 'primary': cid, 'state': md.get('state'), 'published': md.get('datePublished'),
         'modified': md.get('dateUpdated'), 'title': cna.get('title') or '', 'cvss': [], 'cwes': [], 'refs': [],
         'affected': [], 'products': [], 'cna': md.get('assignerShortName')}
    f['description'] = next((d.get('value', '') for d in cna.get('descriptions', []) if (d.get('lang') or '').startswith('en')),
                            (cna.get('descriptions') or [{}])[0].get('value', '') if cna.get('descriptions') else '')
    if md.get('state') == 'REJECTED':
        f['description'] = next((d.get('value', '') for d in cna.get('rejectedReasons', [])), 'Rejected')
    prods = set()
    for by, c in conts:
        for m in c.get('metrics') or []:
            for k in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                if k in m and m[k].get('baseScore') is not None:
                    x = m[k]
                    f['cvss'].append({'score': float(x['baseScore']), 'severity': (x.get('baseSeverity') or band(float(x['baseScore'])) or '').upper(),
                                      'vector': x.get('vectorString'), 'version': k[5:].replace('_', '.'), 'by': 'CNA' if by == 'cna' else by})
        for pt in c.get('problemTypes') or []:
            for d in pt.get('descriptions') or []:
                if d.get('cweId'):
                    f['cwes'].append(d['cweId'])
        for r in c.get('references') or []:
            if r.get('url'):
                f['refs'].append({'url': r['url'], 'tags': r.get('tags') or [], 'by': 'CNA' if by == 'cna' else by})
        for a in c.get('affected') or []:
            hit = catalog.match_affected(a.get('vendor'), a.get('product'), a.get('packageName'), a.get('cpes'))
            if a.get('collectionURL') and a.get('packageName'):  # purl-подобные: packagist/pypi/npm
                eco = {'packagist.org': 'Packagist', 'pypi.org': 'PyPI', 'npmjs.com': 'npm', 'rubygems.org': 'RubyGems'}
                for host, e in eco.items():
                    if host in a['collectionURL']:
                        hit |= catalog.match_affected(ecosystem=e, osv_name=a['packageName'])
            prods |= hit
            if hit or by == 'cna':
                rg, fx = _cve_ranges(a)
                f['affected'].append({'product': sorted(hit)[0] if hit else None, 'vendor': a.get('vendor'), 'name': a.get('product'),
                                      'package': a.get('packageName'), 'ranges': rg, 'fixed': fx, 'by': 'CNA' if by == 'cna' else by})
        for a in c.get('cpeApplicability') or []:
            for n in a.get('nodes') or []:
                prods |= catalog.match_affected(cpes=[x.get('criteria', '') for x in n.get('cpeMatch') or []])
    f['products'] = sorted(prods)
    f['cwes'] = sorted(set(f['cwes']))
    f['affected'] = f['affected'][:40]
    return f


# ---------- OSV (GHSA, PYSEC, GO-…)
def parse_osv(rec):
    oid = rec['id']
    aliases = [a for a in rec.get('aliases') or [] if a]
    cves = sorted(a for a in aliases + [oid] if CVE_RE.match(a))
    f = {'ids': [oid] + aliases, 'primary': cves[0] if cves else None, 'state': 'WITHDRAWN' if rec.get('withdrawn') else 'PUBLISHED',
         'published': rec.get('published'), 'modified': rec.get('modified'), 'title': rec.get('summary') or '',
         'description': (rec.get('details') or '')[:6000], 'cvss': [], 'cwes': [], 'refs': [], 'affected': [], 'products': []}
    for s in rec.get('severity') or []:
        if s.get('type') == 'CVSS_V3':
            sc = cvss3_score(s['score'])
            if sc is not None:
                f['cvss'].append({'score': sc, 'severity': band(sc), 'vector': s['score'], 'version': '3.1', 'by': oid.split('-')[0]})
    ds = rec.get('database_specific') or {}
    if isinstance(ds.get('severity'), str):
        f['severity_label'] = ds['severity'].upper().replace('MODERATE', 'MEDIUM')
    f['cwes'] = sorted(set(ds.get('cwe_ids') or []))
    for r in rec.get('references') or []:
        if r.get('url'):
            f['refs'].append({'url': r['url'], 'tags': [r.get('type', '').lower()], 'by': oid.split('-')[0]})
    prods = set()
    for a in rec.get('affected') or []:
        pk = a.get('package') or {}
        hit = catalog.match_affected(ecosystem=pk.get('ecosystem', ''), osv_name=pk.get('name', ''))
        prods |= hit
        if hit:
            rg, fx = _osv_ranges(a)
            f['affected'].append({'product': sorted(hit)[0], 'ecosystem': pk.get('ecosystem'), 'package': pk.get('name'),
                                  'ranges': rg, 'fixed': fx, 'by': oid.split('-')[0]})
    f['products'] = sorted(prods)
    return f


# ---------- CISA KEV
def parse_kev(e):
    hit = catalog.match_kev(e.get('vendorProject', ''), e.get('product', ''))
    return {'ids': [e['cveID']], 'primary': e['cveID'], 'products': sorted(hit), 'title': e.get('vulnerabilityName') or '',
            'kev': {'added': e.get('dateAdded'), 'due': e.get('dueDate'), 'ransom': e.get('knownRansomwareCampaignUse'),
                    'action': e.get('requiredAction'), 'notes': e.get('notes'), 'vendor': e.get('vendorProject'), 'product': e.get('product'),
                    'desc': e.get('shortDescription')}}
