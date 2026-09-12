# M2c — итоговая приёмка

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-12. Итог: **PASS WITH KNOWN LIMITATIONS**.
M2c принят в согласованном scope reliability/local UI; следующий increment ROADMAP —
read-only Docker posture в M3. M3 этим обновлением документации не реализован и не запущен.

Основа: implementation `afde9f8`, pre-acceptance hardening `48a10f1` и последующий
UI follow-up (navigation/history, Enter/submit, favicon, regression tests).
Phase D выполнена на HEAD `affc09e` с этим follow-up в рабочем дереве;
core-код, Config и dependencies во время host acceptance не менялись.
[Контракт приёмки](M2C-LOCAL-UI.md), [hardening и synthetic validation](M2C-PRE-ACCEPTANCE.md).

## Результаты фаз и происхождение evidence

- **A — PASS:** read-only inspection подтверждена владельцем.
- **B — PASS:** manual browser/UI acceptance подтверждена владельцем после follow-up.
  Это сообщение владельца, а не новый запуск браузера агентом в Phase D.
- **C — service events PASS; timer events not observed.** Подтверждено владельцем.
  Отсутствие timer event в bounded sample не считается defect и не доказывает
  отсутствие timer events вообще. Проверка этого типа остаётся открытой.
- **D — PASS WITH KNOWN LIMITATIONS:** агент выполнил новую отдельную real-host
  серию monitor → view → monitor → view с разрешения владельца.

Первоначальная попытка D признана владельцем незавершённой: его ручной monitor
попал между первым monitor агента и view. Её файлы и первоначальный STOP-отчёт
сохранены без переписывания; результат чистой серии приведён ниже.

## Phase D — наблюдения на host

12 сентября, UTC: monitor 1 — 16:38:27–16:38:29, view 1 — 16:38:29;
monitor 2 — 16:39:14–16:39:16, view 2 — 16:39:16. Все четыре CLI вызова:
**exit 0, stderr пуст**. Полный stdout/JSON, argv, timestamps и exit codes сохранены
отдельно после каждого шага. Обе команды monitor использовали `--iterations 1`,
`uv run --cache-dir .cache/uv --no-sync`, без --config.

[Publication redaction: private workstation observation/configuration omitted.]



- Journal: **first_observation → continuation**, точный checkpoint сохранён.
  Дополнительный bounded read-only probe проверил anchor/provenance существующим
  production adapter; БД от probe не менялась.
- Gap count **1 → 1**: первоначальный first_observation gap сохранился,
  reconciliation_attempted=1, current_state_observed=1, history_recovered=0.
  Timestamp старого journal anchor не выдан за время свежей inventory сверки.
- Reconciliation: **ok → ok**, scans/reconciliation rows **1 → 2**,
  generation=reconciled=1, pending_reconciliation=false.
  **history_recovered=false** во всех monitor/view и gap/reconciliation rows.
- Main DB v2, sidecar v1, checkpoint v1; host/config binding совпадает.
  Baseline revision/rows=0: новая серия не создаёт trusted baseline.
- Обе SQLite дважды quick_check=ok; health bytes=0, storage_failure=false,
  monitor завершён, lock свободен. Хэши/mtime подтверждают read-only поведение view
  и отсутствие неучтённых state writes между captures.
- Network collectors: ok/context_missing; systemd_system: partial/access_or_io;
  systemd_user, accounts, persistence: ok. Этот профиль соответствует принятому
  [M2a coverage limitation](M2A_TRIAL.md). Health честно degraded;
  stale/config mismatch/parser failure в обоих view не обнаружены.
- Journal target events **0 → 0**. Повторный anchor не создаёт event/gap/generation.
  Ненулевой real-event dedup этим idle continuation не подтверждён.
- Inventory snapshots **8 → 9**: у UDP4 одна запись исчезла и одна появилась.
  Новый alert соответствует появившейся записи; прежний стал inactive.
  Active alerts **916 → 916**, total rows **916 → 917**; 915 неизменившихся alerts
  получили ровно +1 occurrence от второго scan. Duplicate contexts и удаления rows
  отсутствуют. Это штатная scan semantics, а не дублирование journal processing.
- Оба view имеют минимизированные проекции: без raw cursor/boot ID/unit names,
  endpoint values, payloads, argv/environment или credentials.
- Notifications **0** (Config.notifications=false; pending не означает отправку),
  LLM disabled, provider calls в выполненном flow **0**, investigations rows=0.

Новых/ухудшившихся ошибок или core defects не обнаружено. Host settings, permissions,
journald retention, services/timers не менялись; новые baseline/trust не создавались.

## Сохранённое локальное evidence

Перед созданием проверено отсутствие всех новых paths, включая dangling symlinks.

- `runtime/m2c-acceptance-clean-20260912/`: watchdog.sqlite3, monitor.lock, storage-health.
- `runtime/m2c-reliability-clean-20260912/`: reliability.sqlite3, reliability-health.
- `runtime/m2c-phase-d-clean-evidence-20260912/`: RESULT.md, SHA256-MANIFEST.json,
  `01/02-monitor` и `01/02-view` stdout/stderr/execution captures, state/checks JSON,
  anchor probe, comparison, alert-side-effects и final-preservation diagnostics.

[Publication redaction: private workstation observation/configuration omitted.]



## Оставшиеся ограничения и переход

Timer presence, новые journal target hints/dedup на ненулевых events, real-host
cursor loss/rotation/reboot, corruption/parser/storage fault injection и lock contention
здесь не проверены. Условия не провоцировались ради PASS. Synthetic regression tests
сохраняют отдельное значение, не заменяют этих наблюдений. Полное auth/system journal
coverage, отсутствие upstream drops и всех transient changes не гарантируются.
Отправка desktop notifications и real AI в эту приёмку не входили.

Полный семидневный M2a/integration soak остаётся на integration/release-candidate
stage; M2b real-provider/model benchmark и human review остаются отдельной работой.
Они не объявлены завершёнными результатом M2c.

Следующий шаг — [первый increment M3 в ROADMAP](../ROADMAP.md#m3--docker-и-developer-security):
определить минимизированный read-only Docker posture contract, способ безопасного
получения данных и synthetic acceptance. Rootful Docker socket остаётся
root-equivalent boundary; начало M3 не разрешает автоматически доступ к нему,
запуск containers, установку scanners или изменение daemon/groups/permissions.

Исторические результаты 195 unittest, M0, Ruff, offline lock, AI benchmark
(provider_calls=0), JS/DOM и package inventory сохранены в pre-acceptance отчёте.
Они не выдаются за повторные тесты во время Phase D; её отдельная проверка —
реальные captures, semantic checks и git diff check.

## Проверка при фиксации документации

2026-09-12, после обновления acceptance/ROADMAP, текущее рабочее дерево:

- `uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py` — PASS.
- `uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests` —
  PASS, **196 tests**, 8.910 s. Это новый прогон с UI follow-up; исторические 195
  в pre-acceptance отчёте не изменяются.
- `uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .` — PASS.
- `uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads`
  — PASS, lock/dependencies не изменены.
- `node --check src/security_orchestrator/local_ui/app.js` и
  `node tests/ui_dom_test.cjs` — PASS, synthetic DOM без network/browser.
- `git diff --check` и проверка существования 73 локальных Markdown link targets — PASS.

Эти проверки не запускают новый host monitor и не меняют сохранённое Phase D evidence.
