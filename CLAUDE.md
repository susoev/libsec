# sec — проект по безопасности

Описание проекта — будет дополнено.

## Код, сайт, git

- Репозиторий: github.com/susoev/libsec (**публичный**, ветка `main`), рабочая копия — сама папка `~/sec`. Секреты, `data/`, `logs/` в `.gitignore` — ничего секретного не коммитить.
- MVP: https://libsec.alid.in → nginx (`deploy/libsec.alid.in.nginx`, сертификат `*.alid.in`) → `app/app.py` на 127.0.0.1:8795, юнит `libsec` (`deploy/libsec.service`). Проверка: `/health`.
- `bin/sync "сообщение"` — коммит, pull --rebase, push; при изменениях в `app/` перезапускает `libsec`, в `deploy/` — переустанавливает юнит/nginx; в конце проверяет сайт.

- `bin/sync` — синхрон с GitHub и выкладка (см. выше).
- `bin/tg`, `bin/dispatch`, `bin/stop-hook` — мост с топиком Sec (см. ниже).
- `.secrets/tg.env` — токен бота (ключ `TG_BOT_MAIN`, меняется через `dok`). Не выводить и никуда не копировать.

## Telegram: топик Sec

Рабочий чат — топик **Sec** (thread 6784), бот tgbridge (@casrvclaudebot).

- **Каждый финальный ответ** любой сессии в этой папке Stop-хук (`bin/stop-hook`) дублирует в топик с припиской `sid:<session_id>`. Сам дублировать не нужно. Отключить для сессии: `SEC_TG=0`.
- **Reply владельца** на сообщение с `sid` будит эту сессию: открыта в консоли (tmux) — текст вставляется в её окно (занята — ждёт); закрыта — фоновый `claude -p --resume <sid>`, после ответа процесс завершается.
- **Сообщение без reply** — новая сессия (чистый контекст: этот файл).
- Входящие: `data/msgs/<ts>-<id>.md`, вложения: `/srv/agent/topics/sec/inbox/`. Промежуточное сообщение: `bin/tg -S <sid> -r <id> 'текст'` (Markdown). Файл: `bin/tg -f путь 'подпись'`.
- Фоновая сессия работает без человека рядом: нужен ответ владельца — спроси в итоговом ответе и закончи ход.

Механика: бот → `data/inbox/` (проект `sec` в `/srv/tgbridge/config/projects.json`, режим inbox) → `sec-chat.path` → `bin/dispatch` (+ `sec-chat.timer` раз в минуту для `data/wait/`). Карта сообщение → сессия: `data/tg.jsonl`. Логи: `logs/`. Установка: `sudo bash install.sh`.
