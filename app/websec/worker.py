"""Воркер: по расписанию запускает коллекторы (у каждого свой интервал, меняется в таблице sources),
затем пересчёт и очередь Telegram. ИИ-анализ — отдельный короткий запуск по таймеру (websec.ai). Один процесс — один писатель SQLite.

  python -m websec.worker            цикл (systemd: websec-worker)
  python -m websec.worker once [имя…]  один проход (все или указанные источники) и выход
  python -m websec.worker reparse      после правки каталога/парсеров: заново разобрать сохранённые записи,
                                       сбросить HTTP-кэш KEV/nginx/OSV-дельт (чтобы взять новые совпадения), пересчитать всё
"""
import json, logging, signal, sys, time, traceback
from . import collectors, pipeline, tg
from .db import connect, dumps, loads

log = logging.getLogger('worker')
TICK = 30
_stop = False


def _sig(*_):
    global _stop
    _stop = True


def ensure_sources(c):
    for m in collectors.ALL:
        c.execute('insert or ignore into sources(name, interval_sec) values(?,?)', (m.NAME, m.INTERVAL))
    c.commit()


def run_source(c, m):
    row = c.execute('select * from sources where name=?', (m.NAME,)).fetchone()
    state = loads(row['cursor'], {}) or {}
    t0 = time.time()
    try:
        n = m.run(c, state)
        pipeline.flush(c)
        c.execute('update sources set last_run=?, last_ok=?, last_error=null, cursor=?, last_new=?, runs=runs+1, fails=0 where name=?',
                  (t0, time.time(), dumps(state), n, m.NAME))
        c.commit()
        log.info('%s: +%d за %.1fs', m.NAME, n, time.time() - t0)
        if n:
            c.execute('update sources set silent_alerted=null where name=?', (m.NAME,))
            c.commit()
    except Exception as e:  # noqa: BLE001
        c.rollback()
        err = f'{type(e).__name__}: {e}'
        log.error('%s: %s\n%s', m.NAME, err, traceback.format_exc())
        c.execute('update sources set last_run=?, last_error=?, runs=runs+1, fails=fails+1, cursor=? where name=?',
                  (t0, err[:1000], dumps(state), m.NAME))
        c.commit()
        fails = c.execute('select fails from sources where name=?', (m.NAME,)).fetchone()[0]
        if fails == 3:
            tg.ops_alert(f'источник {m.NAME} падает 3 раза подряд: {err[:300]}')


def check_silence(c):
    """Источник, который обычно что-то приносит, молчит дольше SILENT_H — скорее сломан парсер, чем тишина."""
    for m in collectors.ALL:
        if not m.SILENT_H:
            continue
        r = c.execute('select * from sources where name=?', (m.NAME,)).fetchone()
        last_new = c.execute('select max(fetched_at) from raw_items where source=?', (m.NAME,)).fetchone()[0]
        if r['last_ok'] and last_new and time.time() - last_new > m.SILENT_H * 3600 and not r['silent_alerted']:
            tg.ops_alert(f'источник {m.NAME} не приносит новых записей {m.SILENT_H}+ ч — проверить парсер')
            c.execute('update sources set silent_alerted=? where name=?', (time.time(), m.NAME))
            c.commit()


def tick(c, only=None, force=False):
    now = time.time()
    for m in collectors.ALL:
        if only and m.NAME not in only:
            continue
        r = c.execute('select * from sources where name=?', (m.NAME,)).fetchone()
        if not r['enabled'] and not force:
            continue
        if force or not r['last_run'] or now - r['last_run'] >= r['interval_sec']:
            run_source(c, m)
            if _stop:
                return
    pipeline.relist(c)
    c.commit()
    try:
        tg.plan_digest(c)
        tg.pump(c)
    except Exception:  # noqa: BLE001
        log.exception('tg')
    c.commit()
    check_silence(c)


def reparse(c):
    from . import normalize
    from .collectors import nginx
    parsers = {'cvelist': normalize.parse_cve, 'cveapi': normalize.parse_cve, 'osv': normalize.parse_osv, 'kev': normalize.parse_kev}
    n = 0
    for r in c.execute('select source, external_id, payload from raw_items').fetchall():
        p = loads(r['payload'])
        if r['source'] in parsers:
            f = parsers[r['source']](p)
        elif r['source'] == 'nginx':
            c.execute('delete from raw_items where source=? and external_id=?', ('nginx', r['external_id']))
            continue
        else:
            continue
        pipeline.attach(c, r['source'], r['external_id'], f)
        n += 1
    for name in ('kev', 'nginx'):
        row = c.execute('select cursor from sources where name=?', (name,)).fetchone()
        st = loads(row[0], {}) or {}
        st.pop('http', None)
        c.execute('update sources set cursor=?, last_run=null where name=?', (dumps(st), name))
    for vid, in c.execute('select id from vulns').fetchall():
        pipeline._dirty.add(vid)
    pipeline.flush(c)
    pruned = pipeline.prune(c)
    c.commit()
    c.execute('vacuum')
    log.info('reparse: %d записей, удалено шумных %d', n, pruned)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    for name in ('httpx', 'httpcore', 'anthropic'):
        logging.getLogger(name).setLevel(logging.WARNING)
    c = connect()
    ensure_sources(c)
    if len(sys.argv) > 1 and sys.argv[1] == 'reparse':
        reparse(c)
        tick(c, only={'kev', 'nginx'}, force=True)
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'once':
        tick(c, only=set(sys.argv[2:]) or None, force=True)
        return
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    while not _stop:
        try:
            tick(c)
        except Exception:  # noqa: BLE001
            log.exception('tick')
        for _ in range(TICK):
            if _stop:
                break
            time.sleep(1)


if __name__ == '__main__':
    main()
