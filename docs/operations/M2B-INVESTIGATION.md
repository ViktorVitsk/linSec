# M2b: расследование по сохранённым evidence

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-11, уточнение endpoint-drift summary: 2026-09-17. Код и synthetic
acceptance реализованы; real-provider acceptance,
сравнение локальных моделей и оценка русского объяснения человеком остаются открытыми.
M2a проходит отдельный real-host trial владельца. Не объявляем этот trial завершённым.

## Что добавлено и что означает результат

`sec investigate ID` читает существующую SQLite v2 в read-only режиме. Без AI settings
возвращает статическое русское объяснение с минимизированными evidence. Для
`endpoint-drift` summary называет тип изменения как сохранённый результат
сравнения на момент формирования alert, а не как новое сопоставление с текущим
baseline; указывает TCP/UDP, IPv4/IPv6, порт и категорию bind, если эти поля есть
в pack. Без исходного принятого baseline текст его не утверждает. Wildcard не
выдаётся за доступность из Интернета, UDP не называется слушающим сервером, а
неполный process context, partial и устаревшее evidence остаются ограничениями.
Тексты берутся из фиксированных шаблонов, без raw telemetry и псевдонимов.
Остальные типы alerts сохраняют общий fallback. Детекторы,
collectors, monitor, baseline и config fingerprint M2a не меняются. Нет миграций,
analysis writes в watchdog DB, новых services или сенсоров. Read transaction заканчивается
до provider call. Отсутствующая/повреждённая база даёт ошибку, не новый пустой inventory.

`--ai-config` задаёт отдельный contract v1 из [ai.example.toml](../../ai.example.toml).
Это не `--config` M2a. `sec status` по-прежнему показывает `llm_enabled=false` для
watchdog: AI работает только в отдельном `investigate`. Старый config/environment
validator сохранён: не задавайте `LLM_ENABLED=true`. Для M2b opt-in используется
`llm_enabled=true` в AI-файле; явно заданный `LLM_ENABLED=false` запрещает даже этот opt-in.
Явный `OPENROUTER_ENABLED=false` также запрещает cloud. `.env` автоматически не читается.

При AI-успехе `answer_untrusted` отделён от неизменённого `deterministic` результата.
Проверка JSON и evidence references не проверяет истинность текста. Человек оценивает
обоснованность фактов и русский язык. Severity, baseline и статус alert не меняются.
Числовой confidence нет. Автоматическое действие всегда отсутствует.

## Privacy и preview

Export pipeline: проверить M2a schema/source/version → проверить связь detector с
before/after → выбрать конкретный object → заменить свободные metadata псевдонимами
→ построить ограниченный pack → показать точное тело запроса, route и бюджет.

В pack остаются IDs, timestamps, source/completeness/staleness, detector metadata,
тип изменения, ограниченные числа (например порт/mode/count), признак UID 0 и bind class.
Пути, имена, UID/GID, адреса, hashes, members, executable и scope заменяются aliases.
Scope/enablement unit экспортируются дословно только при совпадении с закрытым enum;
прочие значения становятся `unknown`. Owners ограничены восемью, members — шестнадцатью;
усечение явно отмечено. Pack ограничен 24 KiB ASCII JSON. Псевдонимы сохраняют равенство
внутри pack, но их номера не являются постоянными идентификаторами между расследованиями.

Не отправляются raw snapshots/history, object keys, free-form reasons, file contents,
argv/env или credentials. Не применяется regex-обещание «удалены все secrets».
Privacy обеспечивается исключением свободных строк из export projection; timestamps,
порты, counts и связи тоже могут быть чувствительны — review обязателен.
Модель может придумать чувствительный текст в ответе; analysis records тоже не публикуйте
автоматически. Ошибки провайдера и hidden reasoning не печатаются/не сохраняются.

Пример на уже существующей **синтетической** базе `sec demo`:

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/watchdog/synthetic-demo alerts
uv run --cache-dir .cache/uv --no-sync sec --state runtime/watchdog/synthetic-demo investigate 1
```

Число `1` заменяется существующим ID из `alerts`. Для настоящего alert используется
реальный `--state`, но сначала review локального `explain`, затем отдельный AI preview.
AI-файл сохраняйте локально, например `runtime/ai.toml`; credentials в нём запрещены.

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/watchdog/synthetic-demo investigate 1 --ai-config runtime/ai.toml
```

Без `--run` сеть не используется даже с enabled settings. Для выбранного provider
команда показывает `request_body`, фиксированный endpoint, ограничения и `approval_token`.
Для запуска добавьте `--run`: интерактивно введите token после просмотра. Можно передать
`--approve TOKEN` для первого точного запроса. Token — локальная привязка review к
данным/параметрам, не credential и не защита от того же UID. Он не даёт согласия на
следующие запросы; каждый новый step требует нового preview/token. В non-interactive
режиме без следующего согласия возвращаются fallback и pending preview, новых calls нет.
Это не resumable session: новый запуск начинает новое расследование и новый бюджет.

Изменение данных во время review останавливает отправку. Следует получить новый preview.
Согласие привязано также к исходной локальной revision, даже если после псевдонимизации
другие данные выглядят одинаково. Raw revision hash не входит в provider request.

## Операции и бюджеты

Строгий ответ имеет `kind`, `summary`, `hypotheses`, `unknowns`, `checks`, `references`,
`operation`, `arguments`. Дополнительные ключи, duplicate JSON keys, превышение размеров
или глубины, неправильные типы и ссылки за пределами pack отклоняются.

Все операции получают только `arguments={id, limit}`:

- `get_alert`: только текущий `alert:ID`, limit=0.
- `get_observation`: snapshot из observations текущего pack, limit=0.
- `compare_baseline`: конкретный `snapshot:ID` принятого baseline из pack, limit=0;
  выдаёт записи и различающиеся поля export projection, не вердикт о чистоте.
- `lookup_runbook`: только подготовленный `runbook:KIND:1`, limit=0; текст из общего
  каталога GUIDANCE, без произвольного чтения файлов.
- `history`: текущий `alert:ID`, limit=1..5; только alerts того же source/object key
  и выбранные связанные observations. Новые evidence входят в следующий privacy preview.

Нет shell/SQL/path/URL/Docker, mutation или вложенного dispatch. Повтор одинаковой операции
останавливает цикл. Во время trial нет AI-recollection: владелец отдельно выполняет
существующий `sec scan`, затем начинает новое расследование с новым preview.

Один call по умолчанию, максимум пять. Лимиты конфигурации: call ≤60 s, run ≤300 s,
output ≤4096 tokens, общий tokens ≤320000, budget ≤10 USD. Дефолты ниже, см. example.
Перед call резервируются input/output tokens и максимальная стоимость по price caps;
резерв не возвращается после ambiguous failure. Консервативная оценка input — размер
ASCII JSON request с schema/framing +512, не точный tokenizer конкретной модели.
Фактический usage сверх резерва останавливает run и не замалчивается.

HTTP request/response body ≤64 KiB, model content ≤32 KiB; нет compression,
redirects, proxy environment routing, retry или cloud escalation. Отдельный transport
process ограничивает ожидание DNS/connect/headers/body; при timeout прекращается только
его выполнение. Cleanup может добавить до двух секунд. Это deadline клиента, не отмена
вычисления/биллинга на сервере. Процесс — не security sandbox и наследует права пользователя;
изоляция coding agent/worker относится к отдельному решению, не «доказана» multiprocessing.

LLM failure, отказ в preview, forbidden op, unknown ID, повтор и исчерпание бюджета
дают deterministic fallback. CLI exit 2 означает незавершённое AI-расследование; это
не изменение health monitor. Exit 0: preview, обычный disabled fallback или AI answer.
Отдельный stdout analysis record содержит versions, request/approval digests, steps,
latency, usage и reserved cost. Нет raw request/response logs в watchdog SQLite.

## OpenRouter: только явный запрос

Нужны provider=`openrouter`, точный model slug, `allowed_providers`, оба enabled flags,
положительные price caps и budget. `OPENROUTER_API_KEY` читается только после согласия,
перед отправкой; никогда не передаётся через CLI arguments, preview или analysis.
Значения цен — integer micro-USD per million tokens; budget — integer micro-USD.
Например budget=25000 означает 0.025 USD; это пример единиц, не рекомендация расходов.

Fixed endpoint: `https://openrouter.ai/api/v1/chat/completions`. Route: `only`,
`allow_fallbacks=false`, `require_parameters=true`, `data_collection=deny`, `zdr=true`,
caps prompt/completion и request/image=0. Endpoint без подходящей policy должен отказать,
не ослабить её. Проверяется возвращённый model и provider (либо selected endpoint metadata),
finish_reason и usage/cost. Используйте точный допустимый provider identifier, совпадающий
с отчётом route; несовместимый ответ даёт fallback. Возможности schema/model проверяются
на synthetic data перед реальным evidence, а не по названию модели.

Пределы биллинга и соблюдение privacy зависят также от OpenRouter/upstream. Для первого
использования нужен отдельный ключ с конечным provider-side credit limit; application
reservation не является банковской гарантией и не ограничивает новые независимые запуски.
Реальных cloud calls при разработке не было, ключи не читались.

## Local benchmark и приёмка

Без inference, только fixed synthetic replay и deterministic fallback:

```bash
uv run --cache-dir .cache/uv --no-sync sec ai-benchmark
```

Для **уже установленного и отдельно проверенного** Ollama: `provider="ollama"`, точный
установленный `model:tag`, `llm_enabled=true`, `local_runtime_verified=true`. Последний флаг
означает проверку владельцем server/model и отключённых cloud features; localhost и
отсутствие `cloud` в имени не доказывают локальность. Требуется local-only конфигурация
Ollama (`OLLAMA_NO_CLOUD=1` на server либо `disable_ollama_cloud`); изменение/перезапуск
сервиса отдельно согласовывается. Адаптер использует только `127.0.0.1:11434/api/chat`,
не pull/install/start, с structured format, ограниченными num_ctx/num_predict, think=false
и keep_alive=0. Освобождение GPU зависит от runtime, timeout не гарантирует выгрузку.

```bash
uv run --cache-dir .cache/uv --no-sync sec ai-benchmark --ai-config runtime/ai.toml --run
```

Это явное согласие на фиксированный **synthetic** corpus локальному runtime, без host
DB/evidence и облака. Для настоящего evidence используйте `investigate` с preview.
Набор `m2b-synthetic-1`: benign change, UID0 anomaly, stale/partial, конфликт со свежим
unavailable source и injection в metadata. Отдельные scripted-provider acceptance tests
покрывают invented IDs, forbidden tools, повтор, budgets, отказ/timeout и новый preview.

[Publication redaction: private workstation observation/configuration omitted.]



## Проверенные API-источники

Локальная проверка реализации 2026-09-11: **93 unittest PASS** (25 M2b + 68 существующих),
Ruff PASS, repository hygiene PASS, offline `uv lock --check` PASS, `git diff --check` PASS.
Отдельный `sec ai-benchmark` прогнал пять fixed synthetic scenarios: provider calls=0,
host collection=false, cloud calls=false. Это проверка конвейера, не inference benchmark.
Удалённый CI, реальные API и GPU/RAM runtime этим не проверены. Зависимости/lockfile
не изменялись; host settings/services не менялись.

Проверены 2026-09-11 для реализации adapters, без исполнения remote snippets:

- [OpenRouter chat completion](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion):
  request/response schema, usage/cost, selected route metadata.
- [OpenRouter provider routing](https://openrouter.ai/docs/guides/routing/provider-selection):
  provider allowlist, parameter support, privacy/ZDR и price caps.
- [Ollama chat](https://docs.ollama.com/api/chat): format, completion limits, timing и keep_alive.
- [Ollama local-only FAQ](https://docs.ollama.com/faq): отключение cloud на сервере.

Архитектурное решение и неизменность trial contracts: [ADR-003](../decisions/ADR-003-m2b-investigation-boundary.md).
