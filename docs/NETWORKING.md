# Сети, прокси и VPN

## Что нужно по умолчанию

VPN для работы RemoteShellBot не требуется.

- Сервер (VPS) принимает WSS и сам ходит в `api.telegram.org` по HTTPS.
- Агент на машине пользователя открывает исходящее WSS-соединение к relay.
- Входящие порты на машине пользователя не открываются.

Прокси или VPN нужны только если сеть блокирует исходящее соединение
агента или сервер не может достучаться до Telegram.

## Диагностика

```
rsb netcheck
rsb netcheck --relay wss://support.example.com --json
rsb netcheck --proxy socks5://127.0.0.1:1080
```

Проверяются DNS, TCP, TLS, HTTP `/healthz`, WebSocket, Telegram API,
системные переменные прокси и активные VPN-интерфейсы. Код возврата `0`,
если relay доступен, иначе `1`.

## `rsb connect`

Единая точка входа для устойчивого подключения агента:

```
rsb connect
rsb connect --proxy http://user:pass@proxy.example:8080
rsb connect --proxy-file ./proxies.txt
rsb connect --no-public-proxies
rsb connect --no-direct --proxy socks5://127.0.0.1:1080
rsb connect --vpn
rsb connect --vpn --vpn-public
rsb connect --vpn --vpn-public --require-vpn
```

Порядок выбора канала:

1. Прямое подключение (если не указан `--no-direct`).
2. `--proxy` (можно повторять).
3. `--proxy-file` или `data/proxies.txt`.
4. Переменные `HTTPS_PROXY`, `ALL_PROXY`.
5. Кэш последних рабочих прокси.
6. Публичные списки с GitHub (если не указан `--no-public-proxies`).
7. WireGuard, если указан `--vpn`.

Каждый кандидат проверяется запросом к `/healthz` через прокси с проверкой
TLS-сертификата. Секрет устройства при проверке не отправляется. Выбирается
самый быстрый рабочий прокси; при обрыве агент переходит к следующему.

При использовании прокси вне loopback разрешён только `wss://`. Открытый
`ws://` через прокси блокируется.

## Файл прокси

`data/proxies.txt` или путь из `--proxy-file`:

```
# строки, начинающиеся с #, игнорируются
http://user:pass@proxy1.example:8080
socks5://proxy2.example:1080
socks5h://proxy3.example:1080
```

Поддерживаются `http`, `https`, `socks5`, `socks5h`. Порт обязателен.
Логины и пароли маскируются в логах и панели.

## Публичные списки прокси

Встроены HTTPS-источники без регистрации:

- `TheSpeedX/PROXY-List` (HTTP и SOCKS5);
- `monosans/proxy-list` (HTTP и SOCKS5);
- `proxifly/free-proxy-list` (HTTP и SOCKS5).

Дополнительные источники можно указать в `RSB_PUBLIC_PROXY_SOURCES`
через запятую. Формат — обычный текст, по одному `host:port` или URL на строку.

Ограничения:

- бесплатные прокси часто умирают, их скорость непредсказуема;
- владелец прокси видит метаданные соединения (IP relay, объём трафика);
- TLS-проверка защищает содержимое WSS, но не гарантирует доступность;
- «всегда работает» на публичных списках гарантировать нельзя.

Поэтому агент проверяет кандидатов, кэширует рабочие и переключается при
обрыве, но публичные прокси — аварийный канал, а не замена своему VPS.

## WireGuard

Публичные списки VPN-конфигов не встроены: автоматически подключаться
к случайным узлам и пропускать через них удалённый shell небезопасно,
а установка туннеля требует прав администратора/root.

Поддерживается:

- обнаружение уже активного VPN (WireGuard, OpenVPN, Tailscale, WARP);
- локальные конфиги в `data/vpn/*.conf`;
- импорт через `rsb vpn add path/to/config.conf`;
- источники в `data/vpn_sources.txt` (по одному URL на строку) или
  `RSB_VPN_SOURCES`;
- `rsb connect --vpn` для локальных конфигов;
- `rsb connect --vpn --vpn-public` для источников;
- `--require-vpn` — не запускать агент, если VPN не поднялся.

Пример `vpn_sources.txt`:

```
https://raw.githubusercontent.com/<owner>/<repo>/<branch>/wireguard.conf
```

Требования и ограничения:

- Windows: установленный WireGuard и запуск от администратора;
- Linux/macOS: `wg-quick` и root (или настроенный `sudo -n`);
- публичные конфиги — недоверенная инфраструктура, трафик идёт через
  чужой узел; используйте только источники, которым доверяете;
- после успешной проверки временный туннель снимается при выходе агента.

```
rsb vpn status
rsb vpn add ./office.conf
```

## Telegram на сервере

Если сервер не может достучаться до `api.telegram.org`, задайте HTTP/SOCKS
прокси:

```
RSB_TELEGRAM_PROXY=socks5://user:pass@proxy.example:1080
```

Для SOCKS установлен `aiohttp-socks`. Проверка:

```
rsb netcheck --relay wss://support.example.com --json
```

## Если relay недоступен снаружи

Прокси на машине пользователя не решает эту задачу: нужен публичный вход.

- **Cloudflare Tunnel**: `cloudflared tunnel --url http://127.0.0.1:8080`
  даёт быстрый публичный адрес без аккаунта; для стабильного домена —
  именованный туннель.
- **SSH reverse tunnel** на VPS:
  `ssh -R 8080:127.0.0.1:8080 user@vps`.
- **Свой VPS + WireGuard** — самый предсказуемый вариант.

После появления публичного адреса укажите его в `RSB_PUBLIC_URL` и
перевыпустите enrollment, если адрес изменился.

## Переменные

| Переменная | Назначение |
|---|---|
| `RSB_AGENT_PROXY` | прокси для агента |
| `RSB_TELEGRAM_PROXY` | прокси для Telegram API |
| `RSB_PROXY_FILE` | файл со списком прокси |
| `RSB_PROXY_TIMEOUT_SECONDS` | таймаут проверки кандидата |
| `RSB_PROXY_CONCURRENCY` | параллельных проверок |
| `RSB_PUBLIC_PROXY_MAX_TEST` | сколько публичных прокси проверять |
| `RSB_PROXY_CACHE_TTL_SECONDS` | срок жизни кэша |
| `RSB_PUBLIC_PROXY_SOURCES` | дополнительные URL списков |
| `RSB_VPN_DIR` | каталог локальных WireGuard-конфигов |
| `RSB_VPN_SOURCES_FILE` | файл с URL VPN-конфигов |
| `RSB_VPN_SOURCES` | дополнительные URL VPN-конфигов |

## Ошибки

| Симптом | Что делать |
|---|---|
| `relay: fail`, TCP ok | проверьте TLS, домен, reverse proxy |
| TCP fail | DNS/сеть/файрвол; попробуйте `rsb connect` |
| Прокси не проходит | проверьте порт и схему; SOCKS5 против HTTP |
| Публичные списки пусты | повторите позже или задайте свой `proxies.txt` |
| VPN требует прав | запустите терминал от администратора/root |
| Telegram API fail | задайте `RSB_TELEGRAM_PROXY` |
