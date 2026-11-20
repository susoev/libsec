# libsec

MVP: https://libsec.alid.in

- `app/` — приложение (сейчас hello world на 127.0.0.1:8795, `/health`).
- `deploy/` — systemd-юнит `libsec.service` и конфиг nginx `libsec.alid.in`.
- `bin/` — мост с Telegram-топиком агента (`tg`, `dispatch`, `stop-hook`), `install.sh` — его установка.
