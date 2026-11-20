"""Публикация в Telegram: очередь tg_queue, лимиты, правила «что срочно».

Правила:
  alert       — новая уязвимость с приоритетом CRITICAL/HIGH или сразу в KEV: отдельным постом
  kev         — уже известная уязвимость попала в CISA KEV (эскалация «эксплуатируется»)
  escalation  — оценка поднялась до HIGH/CRITICAL (было ниже или не было)
  digest      — раз в сутки (DIGEST_HOUR UTC) списком всё остальное новое за сутки
Пост собирается в момент отправки (подхватывает ИИ-резюме, если оно уже готово); alert ждёт ИИ до AI_WAIT.
Канал: WEBSEC_TG_CHAT (+ WEBSEC_TG_THREAD для топика). Пока канала нет — тестовый режим: топик Sec,
не больше WEBSEC_TG_TEST_MAX постов в сутки.
"""
import html, json, logging, os, time
from datetime import datetime, timezone
from pathlib import Path
import httpx
from .db import ROOT, loads

log = logging.getLogger('tg')
ENV_FILE = ROOT / '.secrets/tg.env'
SITE = os.environ.get('WEBSEC_SITE', 'https://websec.in')
PER_MIN = 15           # лимит Telegram ~20/мин в один чат — держим запас
AI_WAIT = 20 * 60      # alert ждёт ИИ-резюме не дольше
DIGEST_HOUR = 9        # UTC
ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNRATED': '⚪'}


def env():
    e = {}
    if ENV_FILE.exists():
        e = dict(l.split('=', 1) for l in ENV_FILE.read_text().splitlines() if '=' in l and not l.startswith('#'))
    chat = os.environ.get('WEBSEC_TG_CHAT') or e.get('TG_CHAT_ID', '').strip()
    thread = os.environ.get('WEBSEC_TG_THREAD', '' if os.environ.get('WEBSEC_TG_CHAT') else e.get('TG_THREAD_ID', '')).strip()
    test = not os.environ.get('WEBSEC_TG_CHAT')
    return {'token': e.get('TG_BOT_TOKEN', '').strip(), 'chat': chat, 'thread': thread, 'test': test,
            'test_max': int(os.environ.get('WEBSEC_TG_TEST_MAX', '3')), 'off': os.environ.get('WEBSEC_TG', '1') == '0'}


def consider(c, v, typ, old):
    E = env()
    if E['off'] or not E['chat']:
        return
    kind = None
    if typ == 'published' and (v['priority'] in ('CRITICAL', 'HIGH') or v['kev']):
        kind = 'alert'
    elif typ == 'kev' and old and old['relevant']:
        kind = 'kev'
    elif typ in ('scored', 'rescored') and v['cvss_severity'] in ('CRITICAL', 'HIGH') and \
            (not old or old['cvss_severity'] not in ('CRITICAL', 'HIGH')) and old and old['relevant']:
        kind = 'escalation'
    if kind:
        c.execute('insert or ignore into tg_queue(chat,thread,kind,vuln_id,status,created) values(?,?,?,?,?,?)',
                  (E['chat'], E['thread'], kind, v['id'], 'new', time.time()))


def esc(s):
    return html.escape(s or '', quote=False)


def products_line(c, v):
    from . import catalog
    return ', '.join(catalog.BY_SLUG[p]['name'] for p in loads(v['products'], []) if p in catalog.BY_SLUG)


def render(c, kind, v):
    a = c.execute('select data from analysis where vuln_id=? and data is not null', (v['id'],)).fetchone()
    ai = loads(a['data']) if a else None
    head = {'alert': '', 'kev': '⚠️ <b>Now exploited in the wild (CISA KEV)</b>\n', 'escalation': '⬆️ <b>Severity raised</b>\n'}[kind]
    pr = v['priority']
    lines = [head + f"{ICON.get(pr, '⚪')} <b>{esc(pr)}</b> · {esc(products_line(c, v))}",
             f"<b>{esc(v['id'])}</b>: {esc(v['title'])}", '']
    if ai and ai.get('summary'):
        lines.append(esc(ai['summary']))
        if ai.get('action'):
            lines += ['', '✅ ' + esc(ai['action'])]
    else:
        d = v['description'] or ''
        lines.append(esc(d[:600] + ('…' if len(d) > 600 else '')))
    fixed = []
    for x in loads(v['affected'], []):
        if x.get('product') and x.get('fixed'):
            fixed.append(f"{x.get('package') or x.get('name') or x['product']} {', '.join(x['fixed'][:4])}")
    if fixed and not (ai and ai.get('action')):
        lines += ['', '✅ Fixed in: ' + esc('; '.join(dict.fromkeys(fixed)))]
    meta = []
    if v['cvss_score'] is not None:
        meta.append(f"CVSS {v['cvss_score']} ({v['cvss_source']})")
    if v['epss'] is not None:
        meta.append(f"EPSS {v['epss']:.1%}")
    if v['kev']:
        meta.append('KEV')
    if meta:
        lines += ['', ' · '.join(meta)]
    lines += ['', f"<a href=\"{SITE}/vuln/{v['id']}\">Details</a>" + (' · AI-assisted summary' if ai else '')]
    return '\n'.join(lines)[:4000]


def render_digest(c, rows):
    out = [f"🗞 <b>Daily digest</b> · {datetime.now(timezone.utc):%Y-%m-%d}", '']
    for v in rows[:40]:
        out.append(f"{ICON.get(v['priority'], '⚪')} <a href=\"{SITE}/vuln/{v['id']}\">{esc(v['id'])}</a> {esc(products_line(c, v))}: {esc((v['title'] or '')[:90])}")
    if len(rows) > 40:
        out.append(f'… +{len(rows) - 40}: {SITE}/')
    return '\n'.join(out)[:4000]


def plan_digest(c):
    E = env()
    if E['off'] or not E['chat']:
        return
    now = datetime.now(timezone.utc)
    if now.hour < DIGEST_HOUR:
        return
    key = f'digest-{now:%Y-%m-%d}'
    c.execute('insert or ignore into tg_queue(chat,thread,kind,vuln_id,status,created) values(?,?,?,?,?,?)',
              (E['chat'], E['thread'], 'digest', key, 'new', time.time()))


def send(token, chat, thread, text):
    d = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML', 'link_preview_options': json.dumps({'is_disabled': True})}
    if thread:
        d['message_thread_id'] = thread
    r = httpx.post(f'https://api.telegram.org/bot{token}/sendMessage', data=d, timeout=30)
    j = r.json()
    if not j.get('ok') and j.get('error_code') == 429:
        raise RuntimeError(f"retry_after {j.get('parameters', {}).get('retry_after')}")
    return j


def pump(c):
    """Отправить созревшее из очереди с учётом лимитов. -> число отправленных."""
    E = env()
    if E['off'] or not E['token']:
        return 0
    now = time.time()
    sent_min = c.execute("select count(*) from tg_queue where status='sent' and sent_at>?", (now - 60,)).fetchone()[0]
    budget = PER_MIN - sent_min
    if E['test']:
        day = c.execute("select count(*) from tg_queue where status='sent' and sent_at>?", (now - 86400,)).fetchone()[0]
        budget = min(budget, E['test_max'] - day)
    from . import ai
    wait = AI_WAIT if ai.enabled() else 0
    n = 0
    for q in c.execute("select * from tg_queue where status='new' order by created").fetchall():
        if budget <= 0:
            if E['test']:  # тестовый режим: лишнее не копим
                c.execute("update tg_queue set status='skipped', error='test cap' where id=?", (q['id'],))
            continue
        if q['kind'] == 'digest':
            since = now - 86400
            rows = c.execute("select * from vulns where listed=1 and feed_ts>? and priority not in ('CRITICAL','HIGH') and kev=0"
                             " order by feed_ts desc", (since,)).fetchall()
            if not rows:
                c.execute("update tg_queue set status='skipped', error='empty' where id=?", (q['id'],))
                continue
            text = render_digest(c, rows)
        else:
            v = c.execute('select * from vulns where id=?', (q['vuln_id'],)).fetchone()
            if not v or not v['listed']:
                c.execute("update tg_queue set status='skipped', error='not listed' where id=?", (q['id'],))
                continue
            has_ai = c.execute('select 1 from analysis where vuln_id=? and data is not null', (v['id'],)).fetchone()
            if q['kind'] == 'alert' and not has_ai and now - q['created'] < wait:
                continue
            text = render(c, q['kind'], v)
        try:
            j = send(E['token'], q['chat'], q['thread'], text)
        except RuntimeError as e:
            log.warning('tg 429: %s', e)
            break
        except httpx.HTTPError as e:
            log.warning('tg: %s', e)
            break
        if j.get('ok'):
            c.execute("update tg_queue set status='sent', sent_at=?, msg_id=?, text=? where id=?",
                      (time.time(), j['result']['message_id'], text, q['id']))
            n += 1
            budget -= 1
        else:
            c.execute("update tg_queue set status='error', error=? where id=?", (j.get('description'), q['id']))
        c.commit()
        time.sleep(1.5)
    return n


def ops_alert(text):
    """Служебный алерт (сломан/молчит источник) в топик Sec."""
    e = {}
    if ENV_FILE.exists():
        e = dict(l.split('=', 1) for l in ENV_FILE.read_text().splitlines() if '=' in l)
    if not e.get('TG_BOT_TOKEN'):
        return
    try:
        send(e['TG_BOT_TOKEN'].strip(), e['TG_CHAT_ID'].strip(), e.get('TG_THREAD_ID', '').strip(), '🛠 websec: ' + esc(text))
    except Exception as ex:  # noqa: BLE001
        log.warning('ops alert: %s', ex)
