"""ИИ-анализ уязвимостей через локальный клиент Claude (подписка), без API и ключей. Решение владельца 2026-11-20.

Схема «разбудить — получить — заснуть»: таймер libsec-ai.timer раз в 10 минут запускает `python -m libsec.ai`.
Если есть свежие записи ленты без разбора (или их факты изменились), процесс будит `claude -p` на пачку до BATCH записей,
получает JSON по схеме, сохраняет в analysis и завершается. Постоянного процесса нет.

Очерёдность: сначала CRITICAL/HIGH/KEV, потом остальное; только записи за последние FRESH_DAYS дней.
Лимит: не больше MAX_BATCHES пачек за запуск и BATCHES_PER_HOUR в час (бережём подписку).
Кэш: analysis(vuln_id, input_hash) — повторный разбор только при изменении фактов.
Защита от выдумок: исправленные версии из ответа сверяются кодом с источниками (verify), ссылки — только из входных refs.
"""
import fcntl, json, logging, os, re, subprocess, sys, time
from . import catalog
from .db import DATA, connect, dumps, loads
from .pipeline import h

log = logging.getLogger('ai')
CLI = os.environ.get('LIBSEC_CLAUDE', '/home/ubuntu/.local/bin/claude')
BATCH = int(os.environ.get('LIBSEC_AI_BATCH', '8'))
MAX_BATCHES = int(os.environ.get('LIBSEC_AI_MAX_BATCHES', '2'))
BATCHES_PER_HOUR = int(os.environ.get('LIBSEC_AI_PER_HOUR', '6'))
FRESH_DAYS = int(os.environ.get('LIBSEC_AI_FRESH_DAYS', '7'))
TIMEOUT = 1200
PROMPT_VERSION = 4

SCHEMA = {
    'type': 'object',
    'properties': {
        'headline': {'type': 'string', 'description': 'Short neutral headline, <= 90 chars, product + flaw type, no CVE id'},
        'summary': {'type': 'string', 'description': '2-4 sentences: what the flaw is and what an attacker can do. Only facts from input.'},
        'affects': {'type': 'string', 'description': 'Who is affected: versions/configurations, in plain words'},
        'preconditions': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Conditions required for exploitation (module enabled, auth needed, non-default config...). Empty if none stated.'},
        'attack_vector': {'type': 'string', 'enum': ['network', 'adjacent', 'local', 'physical', 'unknown']},
        'auth_required': {'type': 'string', 'enum': ['none', 'low', 'high', 'unknown']},
        'vuln_type': {'type': 'string', 'description': 'e.g. RCE, SQL injection, XSS, DoS, info disclosure, privilege escalation, auth bypass, SSRF, memory corruption'},
        'fixed_versions': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Fixed versions exactly as they appear in input facts. Empty if unknown.'},
        'action': {'type': 'string', 'description': 'What to do: upgrade target and, if stated in input, a workaround. One or two sentences.'},
        'our_score': {'type': 'string', 'enum': ['critical', 'high', 'medium', 'low']},
        'score_reasoning': {'type': 'string', 'description': 'Why this score for a typical internet-facing web server running this product; 1-2 sentences.'},
        'typical_server_impact': {'type': 'string', 'enum': ['likely', 'possible', 'unlikely'], 'description': 'Is a typical default web-server deployment exposed?'},
        'sources_used': {'type': 'array', 'items': {'type': 'string'}, 'description': 'URLs from input refs that support the statements'},
    },
    'required': ['headline', 'summary', 'affects', 'preconditions', 'attack_vector', 'auth_required', 'vuln_type', 'fixed_versions',
                 'action', 'our_score', 'score_reasoning', 'typical_server_impact', 'sources_used'],
    'additionalProperties': False,
}

SYSTEM = """You are a vulnerability analyst writing short advisories for administrators of web servers and web applications.
You get facts collected from vulnerability databases (CVE record, OSV/GitHub advisory, CISA KEV, EPSS, vendor pages) as JSON.

Rules:
- Use ONLY the facts provided. Do not add versions, products, exploit details or numbers that are not in the input.
- Never invent or restate a CVSS score; scores are shown separately. Your own `our_score` is a judgement of urgency for a typical internet-facing web server that runs the product, based on attack vector, preconditions, KEV and EPSS.
- If the input lacks something (e.g. fixed version), say it is not stated rather than guessing.
- No exploit code, payloads or step-by-step exploitation instructions.
- `fixed_versions` must be copied verbatim from the input facts.
- `sources_used` must be URLs taken from the input refs.
- Plain, precise English. No marketing, no filler."""


def enabled():
    return os.environ.get('LIBSEC_AI', '1') != '0' and os.path.exists(CLI)


def facts_for(v):
    """Вход модели: только собранные факты (без наших вычисленных полей)."""
    return {
        'id': v['id'], 'aliases': loads(v['aliases'], []), 'title': v['title'], 'description': (v['description'] or '')[:5000],
        'products': [catalog.BY_SLUG[p]['name'] for p in loads(v['products'], []) if p in catalog.BY_SLUG],
        'affected': [{k: a.get(k) for k in ('product', 'vendor', 'name', 'package', 'ecosystem', 'ranges', 'fixed', 'by') if a.get(k)}
                     for a in loads(v['affected'], [])[:15]],
        'cvss': {'score': v['cvss_score'], 'severity': v['cvss_severity'], 'vector': v['cvss_vector'], 'by': v['cvss_source']} if v['cvss_score'] is not None else None,
        'cwe': loads(v['cwes'], []),
        'cisa_kev': {'added': v['kev_added'] and time.strftime('%Y-%m-%d', time.gmtime(v['kev_added'])), 'required_action': v['kev_action'],
                     'ransomware': v['kev_ransom']} if v['kev'] else None,
        'epss': {'probability_30d': v['epss'], 'percentile': v['epss_pct']} if v['epss'] is not None else None,
        'refs': [r['url'] for r in loads(v['refs'], [])[:15]],
        'published': time.strftime('%Y-%m-%d', time.gmtime(v['published'])) if v['published'] else None,
    }


def _norm(s):
    return re.sub(r'[^0-9a-z.]', '', str(s).lower().lstrip('v'))


def verify(out, fin):
    """Сверка кодом: исправленные версии и ссылки должны быть из входных данных."""
    known = {_norm(x) for a in fin['affected'] for x in (a.get('fixed') or [])}
    blob = _norm(json.dumps(fin['affected']) + fin['description'])
    bad = [x for x in out.get('fixed_versions', []) if _norm(x) not in known and _norm(x) not in blob]
    out['fixed_versions'] = [x for x in out.get('fixed_versions', []) if x not in bad]
    refs = set(fin['refs'])
    out['sources_used'] = [u for u in out.get('sources_used', []) if u in refs]
    out['_dropped'] = bad
    return out


def call_cli(batch):
    """batch: [(vuln_id, facts)] -> {vuln_id: анализ}. Один запуск claude -p на всю пачку."""
    items_schema = {'type': 'object', 'properties': {'items': {'type': 'array', 'items': {
        'type': 'object', 'properties': {'id': {'type': 'string'}, **SCHEMA['properties']},
        'required': ['id'] + SCHEMA['required'], 'additionalProperties': False}}}, 'required': ['items']}
    prompt = (SYSTEM + f'\n\nYou get {len(batch)} vulnerabilities. Analyze each one independently, using only its own facts.'
              '\nReturn ONLY a JSON object (no prose, no code fences) matching this JSON Schema, one item per input id:\n'
              + json.dumps(items_schema) + '\n\nInput (JSON):\n' + dumps([{'id': vid, 'facts': f} for vid, f in batch]))
    env = {**os.environ, 'SEC_TG': '0', 'LIBSEC_JOB': '1'}
    p = subprocess.run([CLI, '-p', '--output-format', 'json', '--tools', '', '--setting-sources', '', '--strict-mcp-config',
                        '--no-session-persistence'], input=prompt, capture_output=True, text=True, timeout=TIMEOUT, env=env, cwd='/tmp')
    if p.returncode:
        raise RuntimeError(f'claude -p rc={p.returncode}: {(p.stderr or p.stdout)[-300:]}')
    res = json.loads(p.stdout)
    if res.get('is_error'):
        raise RuntimeError(f"claude -p: {str(res.get('result'))[:300]}")
    text = re.sub(r'^```(json)?|```$', '', res.get('result', '').strip()).strip()
    data = json.loads(text[text.find('{'):text.rfind('}') + 1])
    out = {}
    want = {vid for vid, _ in batch}
    for it in data.get('items') or []:
        vid = it.pop('id', None)
        if vid in want and all(k in it for k in SCHEMA['required']):
            out[vid] = it
    return out


def pending(c, limit):
    rows = c.execute('select v.*, a.input_hash ah, a.error ae, a.created ac from vulns v left join analysis a on a.vuln_id=v.id'
                     ' where v.listed=1 and v.feed_ts > ?'
                     " order by (v.priority in ('CRITICAL','HIGH') or v.kev) desc, v.feed_ts desc",
                     (time.time() - FRESH_DAYS * 86400,)).fetchall()
    todo = []
    for v in rows:
        fin = facts_for(v)
        ih = h([PROMPT_VERSION, fin])
        if v['ah'] == ih and (not v['ae'] or time.time() - (v['ac'] or 0) < 3600):
            continue
        todo.append((v['id'], fin, ih))
        if len(todo) >= limit:
            break
    return todo


def run(c):
    """Одна «побудка»: до MAX_BATCHES пачек. -> число разобранных записей."""
    if not enabled():
        return 0
    done_h = c.execute("select count(distinct created) from analysis where model='claude-cli' and created>?", (time.time() - 3600,)).fetchone()[0]
    n = 0
    for _ in range(min(MAX_BATCHES, max(0, BATCHES_PER_HOUR - done_h))):
        todo = pending(c, BATCH)
        if not todo:
            break
        t0 = time.time()
        try:
            got = call_cli([(vid, fin) for vid, fin, _ in todo])
        except Exception as e:  # noqa: BLE001
            log.warning('пачка %d: %s', len(todo), e)
            got = {}
            err = str(e)[:500]
        else:
            err = 'нет в ответе'
        stamp = time.time()
        for vid, fin, ih in todo:
            if vid in got:
                c.execute('insert or replace into analysis(vuln_id,input_hash,model,data,created,error) values(?,?,?,?,?,null)',
                          (vid, ih, 'claude-cli', dumps(verify(got[vid], fin)), stamp))
                n += 1
            else:
                c.execute('insert or replace into analysis(vuln_id,input_hash,model,data,created,error) values(?,?,?,'
                          '(select data from analysis where vuln_id=?),?,?)', (vid, ih, 'error', vid, stamp, err))
        c.commit()
        log.info('пачка: %d/%d за %.0fs', len(got), len(todo), time.time() - t0)
        if not got:
            break
    return n


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    lk = open(DATA / 'ai.lock', 'w')
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return log.info('уже идёт')
    c = connect()
    if '--status' in sys.argv:
        print(len(pending(c, 10000)), 'в очереди')
        return
    n = run(c)
    if n:
        log.info('разобрано %d', n)


if __name__ == '__main__':
    main()
