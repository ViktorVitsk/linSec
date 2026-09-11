# Local UI: threat model и access control

Дата: 2026-09-11. M2c v1, single-user workstation, foreground, read-only.

## Trust boundary

Недоверенные: remote webpages, browser Origin/headers, HTTP targets, SQLite contents,
telemetry, provider text. Доверенный decision boundary: application/query services
с проверенными schemas. UI — presentation, без collectors, writes, provider clients,
SQL/path/command/operation execution. Watchdog same-UID/root tampering остаётся
ограничением ADR-002/003: UI не превращает local SQLite в tamper-proof evidence.

## Доступ и lifecycle

Только точный bind `127.0.0.1`, порт 1024–65535; `localhost`, IPv6, wildcard, LAN,
произвольные имена отклоняются. Это сокращение поддерживаемого bind surface, не
самостоятельная аутентификация. Не принимать forwarded Host/proxy headers.

Владелец создаёт **новый случайный ключ** 32–128 символов `[A-Za-z0-9_-]` в существующем
password manager и вводит его скрыто при `sec ui`. Ключ не передаётся через argv,
URL, environment, файл, shell history или logs. Ограничение длины не доказывает
энтропию: повторяющаяся или выбранная человеком фраза не подходит.

Процесс хранит digest, сравнивает constant-time; Authorization bearer в браузере
хранится только в JS closure. Нет browser storage/cookies/session DB. Input очищается
сразу после ввода; key не включается в DOM результата, screenshots или diagnostics.
HTTP plaintext ограничен loopback; root/компрометированный browser может видеть
локальную память/трафик. Не использовать proxy, SSH forwarding или remote browser
для реального evidence без отдельной модели угроз.

Срок — 8 часов от запуска. Refresh/reload/pagehide и «Забыть ключ» удаляют browser
credential/evidence; это локальный logout, не server-side revocation bearer в других
вкладках. Остановка foreground процесса отзывает текущий listener. Restart уничтожает
его state, но повторный ввод того же ключа разрешит его снова: нужен новый ключ на
каждый запуск. Нет обещания защищённого стирания Python/JS памяти или clipboard.

## Browser-origin threats

- DNS rebinding: каждый запрос проверяет единственный точный Host с выбранным портом.
  IP loopback bind не делает произвольное DNS-имя доверенным.
- Origin: любой присутствующий Origin обязан точно совпасть со схемой/authority UI;
  null, другая схема/порт/path отвергаются. При отсутствии Origin API требует
  `Sec-Fetch-Site: same-origin`. Дополнительно всегда нужен `X-Sec-UI: 1` и bearer.
  Non-browser client задаёт явный точный Origin. Эти headers не аутентифицируют
  native attacker сами по себе; секретный bearer остаётся необходимым.
- Cross-origin fetch: CORS/credentials/cookies отсутствуют; preflight OPTIONS запрещён,
  custom header и Authorization не допускают simple-request обход.
- CSRF: нет state-changing endpoints вообще. Все методы кроме GET отклоняются;
  даже GET не принимает body/content type/transfer encoding/Expect. Закрытие alerts,
  suppression, baseline, collectors и AI из UI отсутствуют. При будущей mutation
  нужны отдельные explicit policy + POST/CSRF token + Origin/auth tests. Добавления
  одного Handler.do_POST недостаточно: центральный Routes сохраняет deny-by-default.
- Embedded clickjacking: frame-ancestors 'none', X-Frame-Options DENY. Нажатие UI
  кнопок вызывает только чтение; ссылки из telemetry не становятся ссылками.
- XSS/stored prompt injection: только textContent/JSON text, без innerHTML, Markdown,
  eval, generated HTML, LLM output templates. PackBuilder проверяет evidence/detector
  consistency и заменяет произвольные metadata псевдонимами. Bidi/control metadata
  не попадают в браузер через эту проекцию; JSON API ensure_ascii.
- Paths: только `/`, `/app.js`, `/style.css`, `/api/overview`, `/api/alerts`,
  `/api/alerts/<id>`. Нет directory listings, user-selected static path, raw SQL,
  file API или универсальной операции. IDs/pagination проходят bounds и SQL bindings.
- Disclosure: no-store, no-referrer, nosniff, CORP same-origin, COOP same-origin,
  Permissions-Policy. Ошибки фиксированные; request/access/error logs отключены,
  stack traces, headers, raw payloads и keys не выводятся.

CSP: default-src none; только собственные script/style/connect; img/object/base/form
запрещены, remote CDN/fonts/analytics отсутствуют. Browser fetch использует
credentials omit, no-store, redirect error, timeout 7 секунд. UI не выполняет
background polling. Конкретные API ответы ограничены 256 KiB.

## Resource boundary и residual risks

Один последовательный HTTP handler: backpressure без unbounded threads, accept queue 4,
socket inactivity timeout 2 s и общий connection timer 5 s. Timer закрывает только
собственное соединение. SQLite busy timeout 1 s и progress/deadline limits, короткие
read transactions и bounded pagination. Transport Header parser имеет стандартные
верхние пределы Python, после parse действует application cap 8 KiB; target 512 bytes.
Повторные/неожиданные headers и методы отклоняются, сервер закрывает connection.

Локальный вредоносный процесс может занять listener, замедлить UI или читать память
того же пользователя; browser extension может украсть ввод. Это не защищённая от
same-UID компрометации account system. Rate limiting не заменяет random credentials.
UI availability и monitor reliability разделены процессами; медленный browser не
удерживает database transaction во время network response.

Synthetic coverage: authentication/expiry, Host/Origin/CORS, body/method restrictions,
IDs/pagination, duplicate headers through in-memory HTTP parser, hostile evidence,
real UI JS через synthetic DOM, SQLite writer + readers. Sandbox запрещает socket I/O:
реальный TCP listener, browser CSP enforcement/layout и ручная UX-приёмка остаются
в operator checklist. Никакого ослабления sandbox для обхода этого ограничения.

Основание выбора transport и его ограничений:
[Python HTTP server](https://docs.python.org/3.13/library/http.server.html).
