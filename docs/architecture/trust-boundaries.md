# Границы доверия M2a и условия перехода к M2b

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-11. Решения после review перед M2b. Host coverage и семидневная
эксплуатационная приёмка M2a остаются открытыми. Это не подтверждение hardening.

## Watchdog: detection без обещания tamper resistance

M2a показывает drift доступных источников, gaps и историю, пока его процесс,
Python/OS tools, конфигурация и хранилище выполняют предполагаемую функцию.
Он не является независимой доверенной стороной после компрометации того же UID.

Attacker с execution от `dev` потенциально может остановить foreground monitor
или будущий user service, включить kill switch, заменить код/venv/config, изменить
SQLite, timestamps, baseline, suppressions и audit. Root может подделать и источники ОС.
`sec status`, `doctor`, локальные hashes/audit не удостоверяют собственную
достоверность против такого attacker. Отсутствие alerts не доказывает отсутствие
атаки; отсутствие процесса может означать и обычное выключение ПК.

**Решение: documented residual risk M2a.** Не добавляем root daemon, self-protection,
подписи или remote logging ради формального закрытия. Независимый heartbeat,
append-only evidence и изоляция collector требуют отдельного дизайна с независимым
trust anchor. Private files, bounded reads и SQLite checks помогают против ошибок
и части некорректного ввода; это не защита от владельца этих файлов. Семидневный
trial измеряет полезность/надёжность, не tamper resistance. User/root tampering и
TOCTOU того же UID не считаются закрытыми мерами M2a.

## Hostile evidence: конкретные исправления до M2b

Process metadata, executable paths, filenames, usernames, systemd metadata и
сохранённое evidence остаются недоверенными. DB, SHA-256 и accepted baseline не
повышают trust level строки. Доверенная логика detector отделена от этих данных.

**Выполнено сейчас в коде и synthetic tests:**

- Collector использует fixed command registry, `shell=False`, минимальное окружение,
  timeout/output caps и bounded regular-file reads. Telemetry не становится argv.
  Неверный UTF-8 command/file input даёт gap; raw errors не печатаются. Unix filename
  bytes с surrogateescape представляются как escaped data.
- Normalization/DB проверяет allowlisted shapes/types/source kinds, lengths,
  owners/members/records и serialized budget. Размер проверяется по отдельным
  records, до большой общей JSON-строки. Объединённый partial inventory повторно
  ограничен: несколько малых сборов не обходят лимит. SQL values параметризованы.
  Snapshot после чтения из SQLite вновь проходит bounded JSON/schema validation;
  oversized/deep/malformed JSON не становится объектами detector.
- Diff/alert сравнивает структуры и связывает evidence IDs. Нет eval/exec,
  template execution или команд, полученных из data. Строки не могут менять
  detector logic, baseline policy и exceptions сами по себе.
- CLI использует JSON framing и escaping C0/C1, DEL, ESC/OSC/CSI, bidi/format
  controls, surrogates и Unicode line/paragraph separators. **Исправлен пробел
  C1/DEL:** раньше они могли пройти через `ensure_ascii=False`. Русский текст
  остаётся читаемым; JSON round trip сохраняет данные. Argument errors не повторяют
  произвольные values. Это не защита от похожих обычных Unicode букв: имена всё
  равно требуют сопоставления с evidence и контекстом.
- Desktop получает только статическое уведомление о наличии alerts; usernames,
  filenames, порты и другие evidence не передаются в notify-send/desktop bus.

Тесты охватывают SQL/prompt-looking и control strings во всех record types,
DB → explanation → CLI round trip, invalid encoding/shapes/lengths, corrupted stored
JSON, partial union limit, очищенное subprocess environment и статические notifications.
Эти проверки не являются гарантией против attacker, заменившего сам код/Python.

**В дизайне M2b:** escaping терминала не защищает LLM от prompt injection. Нужны
отдельный allowlisted evidence pack, trusted instructions отдельно от untrusted
strings, privacy preview/redaction, typed operations, ID/schema/budget checks.
Модель не получает shell, arbitrary SQL/path/URL, baseline/suppression mutations
или полномочия coding agent. Это должно быть реализовано и проверено до первого
provider call. Сейчас M2a вообще не выполняет LLM/cloud calls.

## Baseline: acknowledged, не clean

Принятый baseline означает **known/acknowledged state конкретного scope и времени**.
Он может быть создан на уже скомпрометированной машине. Он не доказывает легитимность
каждого файла, отсутствие malware или полноту наблюдения. Отсутствие drift — только
совпадение с ранее принятыми наблюдениями.

**До M2b: явно зафиксировать сейчас, выполнено.** Это отражено в baseline preview
CLI и основной архитектуре. Token защищает от принятия другого локального снимка
и stale approval, но не удостоверяет ОС после scan и не authenticates владельца
против attacker под тем же UID. Trust помогает разбирать шум, не является attestation.
Snapshot/audit M1/ответ модели не принимаются автоматически. В M2b baseline —
история решения человека, не clean ground truth.

## Минимизация и secrets

**Проверено сейчас для действующих collectors:**

[Publication redaction: private workstation observation/configuration omitted.]



Synthetic markers в unit Environment, account password field, ss process name и
peer field не появляются в persisted snapshots/explanation; raw-secret fields
отклоняются schema. Никакой cloud secret scanner для этой проверки не запускался.

**Residual risk:** необходимые metadata (path/filename/username) и введённый владельцем
`--reason` тоже могут содержать secret-like текст. Allowlist полей не гарантирует
отсутствие secrets в values. Локальная SQLite не объявляется безопасной для отправки
модели, Git или третьей стороне. Универсальный regex-«очиститель» не добавляем.
**Для M2b:** отдельные export minimization, псевдонимизация, privacy validation и
review конкретного пакета; новые observations требуют нового preview. Raw DB/history
не являются готовым prompt. Переход в LLM не превращает metadata в trusted instructions.

## Coding agent: отдельный потенциально недоверенный процесс

Coding agent и запускаемый им build/test/dependency code могут быть точкой входа:
prompt injection, malicious repository/package/tool output или ошибка генерации.
Доверие к модели не должно автоматически давать процессу все полномочия `dev`.
Эта граница разработки действует уже сейчас, независимо от AI-функций продукта.

**Development policy сейчас:** project-scoped work и минимальные read-only evidence;
за workspace только необходимый scoped доступ. Нет автоматического sudo,
Docker socket/API, privileged containers, agent forwarding, arbitrary `$HOME`,
credentials/browser sessions и environment dumps. Не пробуем эти возможности
«для проверки» без отдельной необходимой задачи и разрешения. Не запускаем Codex
от root и не используем Docker для обхода sandbox/approval. Fixed argv/review и
trusted instruction sources — отдельные слои, а не замена OS isolation.

**Правило поведения не равно техническому ограничению.** `.venv`, AGENTS, Ruff,
private runtime files и clean tests не гарантируют, что процесс coding agent
технически лишён home/socket/sudo access. Фактическая изоляция агента здесь не
менялась и не объявляется проверенной. При доступном rootful Docker socket отсутствие
sudo prompt не устраняет root-equivalent риск. Разработка security monitor не
разрешает агенту автоматически пользоваться этой цепочкой полномочий.

**M3:** Docker posture/privileges/publications/mounts/socket access и режим изоляции
developer workloads. Изменение daemon, групп, socket permissions, отдельного пользователя
или sandbox profile — отдельная поставка с compatibility, approval, verification,
rollback. Rootless runtime и worker без home/socket — возможные альтернативы,
не выбранная/применённая конфигурация. До этого принятый владельцем в M1 риск
`dev → rootful Docker → root-equivalent access` остаётся documented residual risk;
он не является разрешением coding agent на использование этого доступа.

## Listener inventory не Internet reachability

**Проверено и сохранено сейчас.** M2a утверждает только TCP LISTEN/UDP bind в текущем
namespace и доступный context. High для wildcard — приоритет проверки широты bind,
не «открыт в Интернет». Loopback не доказывает отсутствие иных proxy/forwarding/
outbound путей. IPv4/IPv6 рассматриваются раздельно.

Без firewall/NAT/router/external-vantage evidence Internet reachability — **unknown**.
Detector не создаёт поля `internet_reachable`/«WAN open»; они не входят в schema.
В M2b это ограничение вывода модели, которое нельзя заменить предположением.
Docker publications/forwarding posture — M3; external/router validation — отдельная
согласованная проверка. Network probing для формального закрытия M2a не выполняется.

## Условие перехода

Input-handling дефекты исправлены, минимизация проверена синтетически, семантика
baseline и обе trust boundaries зафиксированы. Это не закрывает host/seven-day
trial M2a. В M2b переносим hostile-input scenarios и ограничения источников,
но строим отдельную границу экспорта/действий. Усиление host/agent isolation и
Docker posture не маскируем документацией как применённые меры и не расширяем
ради них M2a без отдельного полезного increment.
