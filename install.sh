#!/bin/bash
# Установка моста: топик Sec (thread 6784) -> ~/sec/data/inbox -> bin/dispatch -> фоновый claude -p в ~/sec -> ответ Stop-хуком в топик.
# Запуск: sudo bash ~/sec/install.sh   (по образцу ~/relo/install.sh)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "нужен sudo"; exit 1; }
O=/home/ubuntu/sec; THREAD=6784; KEY="-1004394348570:$THREAD"; W=/srv/agent/topics/sec
cat > /etc/systemd/system/sec-chat.path <<'U'
[Unit]
Description=Sec: сообщение из топика в data/inbox -> разбудить агента

[Path]
DirectoryNotEmpty=/home/ubuntu/sec/data/inbox
Unit=sec-chat.service

[Install]
WantedBy=multi-user.target
U
sed -e 's#Relo: разбор#Sec: разбор#' -e 's#/home/ubuntu/relo#/home/ubuntu/sec#g' /etc/systemd/system/relo-chat.service > /etc/systemd/system/sec-chat.service
sed -e 's#Relo: повтор#Sec: повтор#' /etc/systemd/system/relo-chat.timer > /etc/systemd/system/sec-chat.timer
setfacl -m u:tgagent:x $O $O/data
setfacl -m u:tgagent:rwx -d -m u:tgagent:rwx,u:ubuntu:rwx $O/data/inbox
install -d -o tgagent -g tgbridge -m 2770 $W $W/inbox $W/outbox $W/outbox/sent
setfacl -R -m u:ubuntu:rwX $W
setfacl -d -m u:ubuntu:rwX $W/inbox
cat > $W/CLAUDE.md <<'M'
# Топик «Sec» → проект `sec`

Сообщения топика уходят файлами в `/home/ubuntu/sec/data/inbox`, агента будит `bin/dispatch`: `claude -p` в `/home/ubuntu/sec`.
Эта папка — только для вложений: `inbox/`.
M
chown tgagent:tgbridge $W/CLAUDE.md; chmod 664 $W/CLAUDE.md
P=/srv/tgbridge/config/projects.json
cp -a $P $P.bak-$(date +%Y%m%d-%H%M)-sec
python3 - "$P" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d['sec'] = {'desc': 'Sec — проект по безопасности (~/sec)',
            'dir': '/home/ubuntu/sec', 'user': 'srv-dev', 'inbox': '/home/ubuntu/sec/data/inbox'}
open(p, 'w').write(json.dumps(d, ensure_ascii=False, indent=1) + '\n')
PY
systemctl stop tgbridge
sudo -u tgagent python3 - "$KEY" "$THREAD" "$W" <<'PY'
import sqlite3, sys, time
key, th, w = sys.argv[1:]; c = sqlite3.connect('/srv/tgbridge/data/bridge.db'); now = time.time()
c.execute("INSERT OR REPLACE INTO topics(key,chat_id,thread_id,name,slug,workdir,session_id,created,updated,server,project)"
          " VALUES(?,?,?,?,?,?,NULL,?,?,NULL,?)", (key, int(key.split(':')[0]), int(th), 'Sec', 'sec', w, now, now, 'sec'))
c.commit()
PY
systemctl start tgbridge
systemctl daemon-reload
systemctl enable --now sec-chat.path sec-chat.timer
sleep 3
systemctl is-active tgbridge sec-chat.path sec-chat.timer
sudo -u tgagent python3 -c "import sqlite3;print(sqlite3.connect('/srv/tgbridge/data/bridge.db').execute(\"select name,project,workdir from topics where key='$KEY'\").fetchone())"
