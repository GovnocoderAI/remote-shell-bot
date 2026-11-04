# Эксплуатация

## Сервер

### Требования

- Linux VPS или выделенная машина.
- Python 3.11 или новее.
- Домен и TLS-сертификат для WSS.
- Reverse proxy: Caddy или nginx.

### Развёртывание

```
sudo useradd --system --home /opt/remote-shell-bot --shell /usr/sbin/nologin rsb
sudo mkdir -p /opt/remote-shell-bot
sudo chown rsb:rsb /opt/remote-shell-bot
sudo -u rsb git clone <repository> /opt/remote-shell-bot/app
sudo -u rsb python3 -m venv /opt/remote-shell-bot/venv
sudo -u rsb /opt/remote-shell-bot/venv/bin/pip install /opt/remote-shell-bot/app
```

Создайте `/etc/remote-shell-bot.env` с правами `0600` и владельцем `root`:

```
RSB_BOT_TOKEN=...
RSB_ADMIN_IDS=100000000
RSB_SECRET_KEY=<32+ случайных байта>
RSB_DATA_DIR=/opt/remote-shell-bot/data
RSB_RELAY_HOST=127.0.0.1
RSB_RELAY_PORT=8080
RSB_PUBLIC_URL=wss://support.example.com
RSB_LOG_LEVEL=INFO
```

Установите unit из `deploy/rsb-server.service`, затем:

```
sudo systemctl daemon-reload
sudo systemctl enable --now rsb-server
sudo systemctl status rsb-server
```

Relay слушает только loopback. TLS завершает reverse proxy, пример для Caddy
находится в `deploy/Caddyfile`.

### Проверка

```
curl -fsS http://127.0.0.1:8080/readyz
```

Ответ содержит статус, число устройств и сессий. `/healthz` — только
liveness без обращения к базе, `/readyz` — готовность с проверкой SQLite.

## Docker

```
cp .env.example .env
docker compose up -d --build
docker compose logs -f relay
```

Сервис публикуется только на `127.0.0.1:8080`, TLS завершает reverse proxy.
SQLite хранится в именованном томе `rsb-data`. Резервная копия:

```
docker run --rm -v remotebot_rsb-data:/data -v "$PWD":/backup alpine \
  sh -c 'apk add --no-cache sqlite && sqlite3 /data/rsb.sqlite3 ".backup /backup/rsb.sqlite3"'
```

Для bind-mount каталога данных заранее выставьте владельца UID 10001.

## Данные

SQLite лежит в `RSB_DATA_DIR/rsb.sqlite3` в режиме WAL. Резервная копия:

```
sudo -u rsb sqlite3 /opt/remote-shell-bot/data/rsb.sqlite3 ".backup '/var/backups/rsb-$(date +%F).sqlite3'"
```

Копируйте файл только через `.backup` или при остановленном сервисе: копирование
WAL-файлов по отдельности даёт несогласованное состояние.

Ключ `RSB_SECRET_KEY` храните отдельно от базы. Без него не расшифровываются
секреты TOTP и секреты устройств.

## Обновление

```
sudo -u rsb /opt/remote-shell-bot/venv/bin/pip install --upgrade /opt/remote-shell-bot/app
sudo systemctl restart rsb-server
```

Активные сессии при перезапуске закрываются. Агенты переподключаются
автоматически с экспоненциальной задержкой.

## Агенты

Установка на машине пользователя:

```
python install.py --relay wss://support.example.com --token <TOKEN> --name <NAME>
```

Автозапуск:

- Windows — задача планировщика при входе пользователя.
- Linux — пользовательский systemd-юнит.
- macOS — launchd.

Автозапуск использует `rsb connect`: сначала прямое подключение, затем
настроенные прокси, `proxies.txt`, кэш и публичные списки. Публичные списки
можно отключить, отредактировав launcher или service и добавив
`--no-public-proxies`. VPN включается только явным `--vpn`.

Агент работает с правами пользователя, который его установил. Запуск от root
или администратора не требуется и не рекомендуется. Для WireGuard права
администратора/root нужны отдельно.

## Ограничения среды

- Снимок экрана требует активной графической сессии. В Wayland захват может
  быть запрещён композитором; в этом случае агент возвращает ошибку.
- На Windows снимок доступен только в сессии вошедшего пользователя.
- При отзыве устройства агент получает код закрытия 4001 и перестаёт
  подключаться до нового enrollment.

## Ротация секретов

1. Выпустите новый enrollment для устройства с `--force`.
2. Отзовите старое устройство командой `/revoke` в боте.
3. При смене `RSB_SECRET_KEY` перевыпустите TOTP операторам через /setup
   и заново зарегистрируйте устройства: старые секреты станут нечитаемыми.
4. `RSB_BOT_TOKEN` меняйте через @BotFather и перезапускайте сервис.

## Логи

Сервер пишет в stdout. Для systemd:

```
journalctl -u rsb-server -f
```

Агент пишет в stdout; локальная панель хранит последние события в памяти.
Журнал команд на сервере очищается по `RSB_AUDIT_RETENTION_DAYS`.
