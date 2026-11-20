# sec — websec, трекер уязвимостей веб-стека

Собирает уязвимости PHP, Python, MySQL, nginx, Apache и других популярных продуктов веб-серверов (каталог — 50 позиций) из CVE List, OSV/GHSA, CISA KEV, EPSS и страниц вендоров. Дедуплицирует их, оценивает срочность, пишет ИИ-резюме и публикует ленту на сайте, RSS, JSON API и посты в Telegram. ТЗ: `docs/brief.md`. Принятые решения: `docs/decisions.md` (новые решения дописывать туда). Устройство кода: `README.md`.

- Воркер: юнит `websec-worker` (`python -m websec.worker`), лог `logs/worker.log`. Один проход: `cd app && ~/venvs/websec/bin/python -m websec.worker once [источник…]`. После правки каталога или парсеров: остановить воркер, `… -m websec.worker reparse`, запустить воркер.
- БД: `data/websec.db` (SQLite). Сайт открывает её только на чтение, пишет только воркер.
- Интервалы источников: таблица `sources.interval_sec`, работает без деплоя. Состояние источников: https://websec.in/status.
- ИИ: `websec-ai.timer` раз в 10 минут запускает `python -m websec.ai` (лог `logs/ai.log`, очередь: `… -m websec.ai --status`). Он будит локальный `claude -p` на пачку до 8 свежих записей, затем переводит готовые разборы, и завершается. Лимит — 6 пачек разбора и 8 вызовов перевода в час.
- Языки: английский на websec.in, переводы на поддоменах `es pt fr de ru zh ja` (язык по Host, `app/websec/i18n.py`). Строки интерфейса — `app/i18n/<lang>.json`; после добавления `_('…')` в шаблоны: `python3 tools/i18n_gen.py es pt fr de ru zh ja`. ИИ-разборы переводит `websec.ai` (таблица `analysis_tr`). Подробности — `docs/decisions.md`.
- TG: пока не задан канал (`WEBSEC_TG_CHAT` в `deploy/websec-worker.service`), посты идут в топик Sec, не больше 3 в сутки.
- Тесты: `cd app && ~/venvs/websec/bin/python -m tests.test_core`.

## Код, сайт, git

- Репозиторий: github.com/susoev/websec.in (**публичный**, ветка `main`), рабочая копия — сама папка `~/sec`. Секреты, `data/`, `logs/` в `.gitignore` — ничего секретного не коммитить.
- Сайт: https://websec.in (с 2026-11-20; домен на Dynadot, DNS там же) → nginx (`deploy/websec.in.nginx`, сертификат `websec.in` + `*.websec.in`, dns-01 через API Dynadot; `www` и поддомены — 301 на websec.in) → uvicorn `websec.web:app` на 127.0.0.1:8795, юнит `websec` (`deploy/websec.service`). Проверка: `/health`.
- `bin/sync "сообщение"` — коммит, pull --rebase, push. Если менялся `app/`, перезапускает `websec` и `websec-worker`; `deploy/` — переустанавливает юниты и nginx; `app/requirements.txt` — ставит зависимости. В конце проверяет сайт. `bin/sync --apply` применяет всё без git.

- `bin/sync` — синхрон с GitHub и выкладка (см. выше).
- `bin/tg`, `bin/dispatch`, `bin/stop-hook` — мост с топиком Sec (см. ниже).
- `.secrets/tg.env` — токен бота (ключ `TG_BOT_MAIN`, меняется через `dok`). Не выводить и никуда не копировать.

## ИИ-анализ: только локальный клиент (решение владельца 2026-11-20)

LLM API (Anthropic/OpenAI/DeepSeek по ключу) **не используем**. ИИ-слой будит локальный `claude -p` (подписка) пачкой на свежие записи, получает аналитику (JSON по схеме) и завершается. Постоянного процесса и API-ключей нет.

## Telegram: топик Sec

Рабочий чат — топик **Sec** (thread 6784), бот tgbridge (@casrvclaudebot).

- **Каждый финальный ответ** любой сессии в этой папке Stop-хук (`bin/stop-hook`) дублирует в топик с припиской `sid:<session_id>`. Сам дублировать не нужно. Отключить для сессии: `SEC_TG=0`.
- **Reply владельца** на сообщение с `sid` будит эту сессию: открыта в консоли (tmux) — текст вставляется в её окно (занята — ждёт); закрыта — фоновый `claude -p --resume <sid>`, после ответа процесс завершается.
- **Сообщение без reply** — новая сессия (чистый контекст: этот файл).
- Входящие: `data/msgs/<ts>-<id>.md`, вложения: `/srv/agent/topics/sec/inbox/`. Промежуточное сообщение: `bin/tg -S <sid> -r <id> 'текст'` (Markdown). Файл: `bin/tg -f путь 'подпись'`.
- Фоновая сессия работает без человека рядом: нужен ответ владельца — спроси в итоговом ответе и закончи ход.

Механика: бот → `data/inbox/` (проект `sec` в `/srv/tgbridge/config/projects.json`, режим inbox) → `sec-chat.path` → `bin/dispatch` (+ `sec-chat.timer` раз в минуту для `data/wait/`). Карта сообщение → сессия: `data/tg.jsonl`. Логи: `logs/`. Установка: `sudo bash install.sh`.
