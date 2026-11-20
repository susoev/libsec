"""SQLite (WAL): один файл data/libsec.db. Пишет воркер, сайт только читает."""
import json, os, sqlite3, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get('LIBSEC_DATA', ROOT / 'data'))
DB = Path(os.environ.get('LIBSEC_DB', DATA / 'libsec.db'))

SCHEMA = """
create table if not exists sources(
  name text primary key, interval_sec int not null, enabled int default 1,
  last_run real, last_ok real, last_error text, cursor text,
  last_new int default 0, runs int default 0, fails int default 0, silent_alerted real
);
-- сырые записи источников (только релевантные каталогу или уже известные уязвимости)
create table if not exists raw_items(
  source text, external_id text, url text, hash text, payload text, fetched_at real, processed int default 0,
  primary key(source, external_id)
);
create index if not exists raw_unproc on raw_items(processed) where processed = 0;
-- нормализованные факты каждого источника об уязвимости: из них пересчитывается vulns
create table if not exists facts(
  vuln_id text, source text, external_id text, data text, updated real,
  primary key(vuln_id, source, external_id)
);
create table if not exists aliases(alias text primary key, vuln_id text);
create index if not exists aliases_v on aliases(vuln_id);
create table if not exists vulns(
  id text primary key, aliases text, state text, title text, description text,
  published real, modified real,
  cvss_score real, cvss_severity text, cvss_vector text, cvss_version text, cvss_source text,
  cwes text, refs text, affected text, products text,
  kev int default 0, kev_added real, kev_due real, kev_ransom text, kev_action text,
  epss real, epss_pct real, epss_date text,
  priority text, priority_reason text,
  relevant int default 0, listed int default 0, feed_ts real,
  created real, updated real
);
create index if not exists vulns_feed on vulns(listed, feed_ts desc);
create table if not exists vuln_products(vuln_id text, product text, primary key(vuln_id, product));
create index if not exists vp_p on vuln_products(product);
create table if not exists events(
  id integer primary key, vuln_id text, type text, key text, data text, ts real,
  unique(vuln_id, type, key)
);
create index if not exists events_v on events(vuln_id);
create index if not exists events_ts on events(ts desc);
-- ИИ-анализ: кэш по (vuln_id, хэш входных фактов)
create table if not exists analysis(
  vuln_id text primary key, input_hash text, model text, data text, created real, error text
);
-- очередь Telegram
create table if not exists tg_queue(
  id integer primary key, chat text, thread text, kind text, vuln_id text, text text,
  status text default 'new', created real, sent_at real, msg_id int, error text,
  unique(chat, kind, vuln_id)
);
"""


def connect(readonly=False):
    DATA.mkdir(parents=True, exist_ok=True)
    if readonly:
        c = sqlite3.connect(f'file:{DB}?mode=ro', uri=True, timeout=10, check_same_thread=False)
    else:
        c = sqlite3.connect(DB, timeout=30)
        c.execute('pragma journal_mode=wal')
        c.execute('pragma synchronous=normal')
        c.executescript(SCHEMA)
    c.row_factory = sqlite3.Row
    c.execute('pragma busy_timeout=10000')
    return c


def dumps(o):
    return json.dumps(o, ensure_ascii=False, separators=(',', ':'), sort_keys=True, default=str)


def loads(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default


now = time.time
