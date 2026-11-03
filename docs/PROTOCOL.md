# Протокол

## Транспорт

WebSocket, текстовые кадры, JSON. Один кадр — один конверт. Бинарные данные
передаются только в base64 внутри JSON.

```
{ "type": "session.request", "id": "8f3c...", "ref": null, "payload": { } }
```

- `type` — имя сообщения, до 64 символов.
- `id` — уникальный идентификатор сообщения, 32 hex-символа.
- `ref` — идентификатор запроса, на который отвечает сообщение, или `null`.
- `payload` — объект.

Лимиты: управляющий кадр до 64 KiB, общий кадр до 8 MiB. Превышение
закрывает соединение с кодом 1009.

## Рукопожатие

Агент после установления WebSocket отправляет:

```json
{
  "type": "hello",
  "id": "...",
  "payload": {
    "device_id": "uuid",
    "nonce": "32 hex",
    "timestamp": 1730000000,
    "signature": "hex hmac sha256"
  }
}
```

Подпись: `HMAC-SHA256(device_secret, device_id + "|" + nonce + "|" + timestamp)`.

Сервер проверяет устройство, окно времени и nonce, после чего отвечает:

```json
{
  "type": "hello.ok",
  "payload": {
    "server_time": 1730000000,
    "session_ttl": 1800,
    "request_ttl": 180,
    "device": {
      "id": "uuid",
      "name": "office-pc",
      "hostname": "office-pc.local",
      "os_name": "Linux",
      "capabilities": ["shell"]
    },
    "grants": [
      {
        "operator_id": 100000000,
        "capabilities": ["shell"],
        "updated_at": "2026-01-01T12:00:00Z"
      }
    ]
  }
}
```

Поле `capabilities` в `device` — политика, разрешённая хостом. `grants` —
последние выданные права по операторам, для отображения в панели.

При ошибке сервер отправляет `hello.error` и закрывает соединение.

## Сообщения сервер → агент

### session.request

```json
{
  "session_id": "uuid",
  "operator": { "id": 100000000, "username": "admin" },
  "purpose": "support",
  "requested_capabilities": ["shell", "screenshot"],
  "previous_capabilities": ["shell"],
  "requested_at": "2026-01-01T12:00:00Z",
  "expires_at": "2026-01-01T12:15:00Z"
}
```

`previous_capabilities` может быть `null`, если оператор ранее не получал
доступ к устройству.

### session.approved

```json
{
  "session_id": "uuid",
  "capabilities": ["shell", "screenshot"],
  "account": {
    "id": "uuid",
    "username": "rsb-1a2b3c",
    "token": "secret",
    "expires_at": "..."
  },
  "operator": { "id": 100000000, "username": "admin" },
  "purpose": "support",
  "expires_at": "..."
}
```

`capabilities` — окончательный набор прав, выданный хостом. Он не может
превышать `requested_capabilities`.

### session.denied

```json
{ "session_id": "uuid", "reason": "host_denied" }
```

### session.close

```json
{ "session_id": "uuid", "reason": "operator_closed" }
```

### session.update

```json
{ "session_id": "uuid", "capabilities": ["shell"] }
```

Сервер сообщает агенту, что набор прав действующей сессии сокращён.
Права можно только уменьшать; расширение выполняется новой сессией.

### command.exec

```json
{
  "session_id": "uuid",
  "account_token": "secret",
  "command": "ls -la",
  "cwd": "/home/user"
}
```

Ответ (`command.result`):

```json
{
  "exit_code": 0,
  "output": "text",
  "cwd": "/home/user",
  "truncated": false,
  "timed_out": false
}
```

### screenshot.request

```json
{ "session_id": "uuid", "account_token": "secret" }
```

Запрос отправляется только если в сессии выдано право `screenshot`. Агент
проверяет право повторно и при отсутствии отвечает ошибкой.

Ответ (`screenshot.result`):

```json
{ "image": "base64 jpeg", "width": 1600, "height": 900, "taken_at": "..." }
```

Ошибка (`screenshot.result`):

```json
{ "error": "screenshot capability is not granted" }
```

### policy.updated

```json
{ "capabilities": ["shell", "screenshot"] }
```

Подтверждение новой политики после `policy.update` от агента. Сервер
самостоятельно сокращает права активных сессий до новой политики, закрывает
сессии без оставшихся прав и отклоняет ожидающие запросы, которые больше
не проходят по политике (`policy_changed`).

### grant.revoked

```json
{ "operator_id": 100000000 }
```

Подтверждение отзыва сохранённых прав оператора.

## Сообщения агент → сервер

### session.decision

```json
{
  "session_id": "uuid",
  "approved": true,
  "capabilities": ["shell"]
}
```

При отказе:

```json
{ "session_id": "uuid", "approved": false, "reason": "host_denied" }
```

### session.close_request

```json
{ "session_id": "uuid", "reason": "host_closed" }
```

### audit.event

```json
{ "session_id": "uuid", "action": "command", "detail": { "command": "ls" } }
```

### policy.update

```json
{ "capabilities": ["shell"] }
```

Новая политика устройства, заданная владельцем в локальной панели.
Сервер отвечает `policy.updated` с нормализованным набором.

### grant.revoke

```json
{ "operator_id": 100000000 }
```

Отзыв сохранённых прав оператора. Сервер отвечает `grant.revoked`.

### session.capabilities

```json
{ "session_id": "uuid", "capabilities": ["shell"] }
```

Запрос хоста на сокращение прав активной сессии. Сервер проверяет, что новый
набор является подмножеством текущего, обновляет сессию и учётную запись,
после чего отправляет `session.update`. Если набор пуст, сессия закрывается.

### heartbeat

```json
{ "sent_at": 1730000000 }
```

Служебные ответы всегда содержат `ref` исходного сообщения. Сервер
коррелирует ответы по `ref`; неизвестный `ref` игнорируется.

## Коды закрытия

| Код | Причина |
|---|---|
| 1000 | нормальное завершение |
| 1008 | нарушение политики, неверная подпись |
| 1009 | превышен размер кадра |
| 1011 | внутренняя ошибка |
| 4001 | устройство отозвано |
| 4002 | повторное подключение устройства |
