"""ИИ-анализ уязвимости: резюме, кого касается, что делать, своя оценка — строго по собранным фактам, строгая JSON-схема.

Провайдеры:
  api  — Anthropic API (ключ ANTHROPIC_API_KEY в .secrets/ai.env; в хранилище — CLAUDE_API_CA). Основной режим.
  cli  — локальный `claude -p` (подписка): только если ключа нет, и лишь для CRITICAL/HIGH/KEV, не больше CLI_PER_HOUR.
Кэш: таблица analysis (vuln_id, input_hash) — повторный анализ только при изменении фактов.
Защита от выдумок: версии в ответе ИИ сверяются кодом с версиями из источников (verify); не совпало — поле отбрасывается.
"""
import json, logging, os, re, subprocess, time
from . import catalog
from .db import ROOT, dumps, loads
from .pipeline import h

log = logging.getLogger('ai')
AI_ENV = ROOT / '.secrets/ai.env'
MODEL = os.environ.get('LIBSEC_AI_MODEL', 'claude-opus-5-5')
CLI = '/home/ubuntu/.local/bin/claude'
CLI_PER_HOUR = int(os.environ.get('LIBSEC_AI_CLI_PER_HOUR', '4'))
API_PER_RUN = int(os.environ.get('LIBSEC_AI_PER_RUN', '20'))
PROMPT_VERSION = 3

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


def key():
    if os.environ.get('ANTHROPIC_API_KEY'):
        return os.environ['ANTHROPIC_API_KEY']
    if AI_ENV.exists():
        for l in AI_ENV.read_text().splitlines():
            if l.startswith('ANTHROPIC_API_KEY='):
                return l.split('=', 1)[1].strip().strip('"\'') or None
    return None


def enabled():
    return os.environ.get('LIBSEC_AI', '1') != '0' and (bool(key()) or os.path.exists(CLI))


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


def call_api(fin):
    import anthropic
    client = anthropic.Anthropic(api_key=key(), max_retries=3, timeout=180)
    r = client.beta.messages.create(
        model=MODEL, max_tokens=4000, system=SYSTEM,
        betas=['server-side-fallback-2026-07-01'], fallbacks='default',
        output_config={'effort': 'medium', 'format': {'type': 'json_schema', 'schema': SCHEMA}},
        messages=[{'role': 'user', 'content': 'Facts (JSON):\n' + dumps(fin)}],
    )
    if r.stop_reason == 'refusal':
        raise RuntimeError('refusal')
    text = next(b.text for b in r.content if b.type == 'text')
    return json.loads(text), r.model


def call_cli(fin):
    prompt = (SYSTEM + '\n\nReturn ONLY a JSON object (no prose, no code fences) matching this JSON Schema:\n' + json.dumps(SCHEMA)
              + '\n\nFacts (JSON):\n' + dumps(fin))
    env = {**os.environ, 'SEC_TG': '0', 'LIBSEC_JOB': '1'}  # без Stop-хука в топик
    p = subprocess.run([CLI, '-p', '--output-format', 'json', '--tools', '', '--setting-sources', '', '--strict-mcp-config',
                        '--no-session-persistence'],
                       input=prompt, capture_output=True, text=True, timeout=600, env=env, cwd='/tmp')
    if p.returncode:
        raise RuntimeError(f'claude -p: {p.stderr[-300:] or p.stdout[-300:]}')
    res = json.loads(p.stdout)
    text = res.get('result', '').strip()
    text = re.sub(r'^```(json)?|```$', '', text).strip()
    out = json.loads(text[text.find('{'):text.rfind('}') + 1])
    miss = [k for k in SCHEMA['required'] if k not in out]
    if miss:
        raise ValueError(f'нет полей {miss}')
    return out, 'claude-cli'


def run(c):
    """Проанализировать ещё не разобранные (или изменившиеся) уязвимости ленты. -> число готовых."""
    if not enabled():
        return 0
    api = bool(key())
    if api:
        limit, cond = API_PER_RUN, ''
    else:
        done_h = c.execute("select count(*) from analysis where model='claude-cli' and created>?", (time.time() - 3600,)).fetchone()[0]
        limit = CLI_PER_HOUR - done_h
        cond = " and (priority in ('CRITICAL','HIGH') or kev=1) and feed_ts > strftime('%s','now') - 7*86400"
    if limit <= 0:
        return 0
    rows = c.execute('select v.*, a.input_hash ah, a.error ae, a.created ac from vulns v left join analysis a on a.vuln_id=v.id'
                     f' where v.listed=1{cond} order by (v.priority in (\'CRITICAL\',\'HIGH\') or v.kev) desc, v.feed_ts desc limit 400').fetchall()
    n = 0
    for v in rows:
        if n >= limit:
            break
        fin = facts_for(v)
        ih = h([PROMPT_VERSION, fin])
        if v['ah'] == ih and (not v['ae'] or time.time() - (v['ac'] or 0) < 3600):
            continue
        try:
            out, model = call_api(fin) if api else call_cli(fin)
            out = verify(out, fin)
            c.execute('insert or replace into analysis(vuln_id,input_hash,model,data,created,error) values(?,?,?,?,?,null)',
                      (v['id'], ih, model, dumps(out), time.time()))
            n += 1
            log.info('ai %s %s -> %s', v['id'], model, out.get('our_score'))
        except Exception as e:  # noqa: BLE001 — сбой одной записи не роняет цикл
            log.warning('ai %s: %s', v['id'], e)
            c.execute('insert or replace into analysis(vuln_id,input_hash,model,data,created,error) values(?,?,?,'
                      '(select data from analysis where vuln_id=?),?,?)', (v['id'], ih, 'error', v['id'], time.time(), str(e)[:500]))
            if not api:
                break
        c.commit()
    return n
