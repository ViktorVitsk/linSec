# ADR-007 — минимальный orchestrator: готовые инструменты прежде собственного кода

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата исследования и решения: **2026-09-13**. Основание: прямой запрос владельца
перепроверить M2/M3 и самостоятельно сократить ненужную реализацию.
Статус: **направление принято; первое сокращение реализовано**.
Заменяет приоритет дальнейшего развития ADR-001/004/005/006, но не переписывает
их историческую приёмку и не разрешает изменения хоста.

## Уточнение владельца после аудита — 2026-09-13

Ближайшая работа — оценка существующего M2a в течение 5–7 обычных рабочих дней,
после отдельного разрешения запуска. Новые функции не разрабатываются; к коду
возвращаемся только ради подтверждённой проблемы. Collectors, SQLite, reviewed
baseline/diff и scheduler сохраняются. Gitleaks integration и osquery pilot отложены,
systemd timer необязателен. M2b/M2c/UI сохраняются без расширения; старую M3 acceptance
не продолжать. Работающий компонент заменять только при доказуемой пользе выше
стоимости и риска миграции, независимо от уже затраченного времени.

Это уточнение имеет приоритет над рекомендациями WRAP/REPLACE и порядком миграции
ниже: они сохраняют контекст аудита и возможные варианты, но не задают обязательные
следующие шаги. Результаты исследования и исторических проверок не переписаны.
[Текущий roadmap](../ROADMAP.md), [процедура M2a](../operations/M2A-WATCHDOG.md#m2a-daily-trial).

## Решение по компонентам

KEEP означает поддерживать собственную логику. WRAP — сохранить нашу границу,
использовать готовый источник; это не утверждение, что миграция уже выполнена.
REPLACE — изменить механизм. REMOVE — убрать из продукта. DEFER — прекратить
развитие до конкретной потребности; временно доступный legacy код отмечен отдельно.

| Current component | Existing alternative | Решение | Причина |
| --- | --- | --- | --- |
| M2a network: `parse_ss`, `owner_context` | osquery `listening_ports` + выбранные поля processes; штатный `ss` | **WRAP** | Перенести OS inventory в osquery, если короткий pilot подтверждает TCP/UDP, IPv4/6, ownership и неполноту. До этого bounded `ss` adapter остаётся; второй постоянный collector не добавлять. |
| M2a local users/groups | osquery `users`, `groups`, `user_groups` | **WRAP** | Не развивать свой account inventory. Проверить primary/supplementary membership и local-only scope; ошибочный/пустой результат не означает удаление всех accounts. |
| System/user units, enablement, drop-ins | systemd `systemctl`/D-Bus; osquery `systemd_units` для другого scope | **WRAP** | Уже оборачиваем systemd. osquery не заменяет все установленные unit-файлы и user manager; оставить узкий адаптер и не расширять собственную модель systemd. |
| Выбранные persistence files / hashes | osquery `file`/`hash`; AIDE для полноценного FIM | **WRAP** | Сохранить ограниченный список и privacy contract. Не строить рекурсивный FIM; AIDE подключать только при необходимости более широкого контроля. |
| SQLite inventory/history M2a | SQLite уже зрелая библиотека; osqueryd differential log решает другую задачу | **KEEP** | Хранить минимизированные observations и решения владельца. Не копировать полные inventory/логи внешних инструментов и не заменять SQLite серверной БД. |
| Reviewed baseline, diff, lifecycle | osqueryd diff / AIDE reference DB | **KEEP** | Изменение последнего observation не равно принятию baseline. Сохранить review, source scope, версии и запрет ложных removals. Небольшой object diff не generic rule engine. |
| Trust/suppression и audit | Scanner ignore/allowlist | **KEEP** | Контекст, причина, срок, отзыв и независимость от закрытия alert — политика владельца. Upstream ignore не должен незаметно скрывать evidence. |
| Provenance, partial/unavailable, freshness | Статусы/exit codes инструментов | **KEEP** | Наш слой обязан различать результат проверки, доступность источника и отсутствие данных. Код возврата scanner часто означает findings, а не failure. |
| M2a/M2c циклы расписания | systemd user timer + одноразовый `sec scan` | **REPLACE** | Один scheduler. В целевой поставке нет Python-daemon scheduler поверх systemd. Сейчас legacy команды сохранены; unit installation и проверка kill switch — отдельный согласованный шаг. |
| M2c journal cursor/gaps/reconciliation | journald, `journalctl`, sd-journal API | **DEFER** | Сложный sidecar и 5-секундный polling ради трёх user-unit transitions пока не оправданы пользой. Не расширять до auth log platform. При возврате событий использовать штатный cursor API; gap semantics сохранить. |
| Local HTTP/UI | CLI; upstream reports; Cockpit для управления ОС | **DEFER** | Не поддерживать новый универсальный dashboard. Legacy M2c UI остаётся без расширения; общий query/поясняющий слой нужен CLI. Cockpit не устанавливать ради нашего экрана. |
| M3 synthetic SQLite, dedup/drift, demo, UI | Общий future report admission; сейчас достаточно файлов capture | **REMOVE** | Отдельная модель только для fixtures не приносит host detection. Удаляются store, demo, CLI/API/UI пути и их специфичные tests. |
| `docker-acquire`, projection, `docker-review` | Официальный Docker CLI; ручной ограниченный export | **KEEP**, ограниченный legacy scope | Это уже adapter к Docker, а не реализация Engine. Сохранить проверку исторических captures и minimization; не интегрировать в постоянный monitor и не продолжать acceptance без новой потребности. |
| Развитие Docker posture rules | Docker Bench для CIS; Trivy для image/IaC, другие scope | **WRAP** | Прекратить наращивание собственной библиотеки checks. Текущие маленькие правила остаются для offline review прежнего capture. Новые проверки импортировать с upstream ID/version/coverage; не обещать прямую замену runtime снимка Trivy. |
| Secret scanning | Gitleaks; Betterleaks как кандидат преемника | **WRAP** | Готовый scanner, фиксированный scope, redaction и минимизированные findings. Собственного secret detector нет и не будет. |
| Vulnerabilities / SBOM / IaC | Trivy **или** Grype; Syft при отдельной потребности в SBOM | **WRAP** | Один основной vulnerability scanner. Предпочтение Trivy при потребности и в IaC; Grype — альтернатива для CVE-only. Не ставить оба автоматически. |
| M2b packs, privacy preview, bounded investigation, fallback | Provider API/SDK; generic agent frameworks | **KEEP** | Собственная policy оправдана: точный payload, бюджет, только связанные evidence IDs, нет shell/SQL/path/URL. Не расширять до agent framework; AI остаётся optional и выключенным. |
| Model benchmark, persistent AI timeline, новые providers | Готовые runtime, ручная оценка нескольких примеров | **DEFER** | Реальная польза AI пока не подтверждена. Не строить observability/eval платформу вокруг опционального объяснения. |
| Generic rules/workflows/CTI/SIEM | Sigma engines, Falco, Wazuh, Fleet, OpenCTI/MISP | **DEFER** | Для одного workstation нет задачи, оправдывающей эту инфраструктуру. Не писать собственные аналоги. |

## Что показал код

Проверены root/global AGENTS, чистый `git status` на старте, README, roadmap,
ADR-001–006, архитектура, M2 acceptance/operations и реализация с synthetic tests.
Исходная точка — Git `2046f65`. По исходникам до сокращения:
`adapters/linux.py` — 474 строки; journal adapter — 184; M2c runtime/store — 85/272;
Docker synthetic store — 347; HTTP server — 241; JS — 310.
Это размеры файлов, не доказательство качества или объём всех dependencies.

[Publication redaction: private workstation observation/configuration omitted.]



Тесты содержат ценность на границах: partial→complete и reviewed baseline,
отсутствие false removals, scope mismatch, narrow exceptions, hostile strings,
LLM-off, новые privacy approvals, rollback/cursor и отказ HTTP до чтения DB.
Tests внутренней synthetic БД не являются самостоятельным основанием хранить её.

## Обзор внешних компонентов

[Publication redaction: private workstation observation/configuration omitted.]



| Инструмент и поддержка/лицензия | Права, нагрузка, совместимость и интеграция | Что заменяет / выбор |
| --- | --- | --- |
| **osquery/osqueryd**: release 5.23.1 от 24.06.2026 с security fixes; Apache-2.0 OR GPL-2.0-only. [Releases](https://github.com/osquery/osquery/releases), [license](https://raw.githubusercontent.com/osquery/osquery/master/LICENSE). | Linux binary; обычный UID даёт лишь доступную ему видимость. Daemon имеет scheduler/differential logs/watchdog, но watchdog не OS sandbox; query cost надо измерить. Fixed SQL/columns, no distributed queries/extensions/audit/BPF/carving. Средняя стоимость интеграции. [Performance](https://osquery.readthedocs.io/en/stable/deployment/performance-safety/), [logging](https://osquery.readthedocs.io/en/stable/deployment/logging/). | Лучший кандидат для части M2a inventory. Сначала osqueryi, без второго daemon; osqueryd только если его scheduling реально заменит выбранный механизм. |
| **Fleet**: maintained osquery/MDM product; основной код MIT, `ee/` отдельно. [License](https://raw.githubusercontent.com/fleetdm/fleet/main/LICENSE), [project](https://fleetdm.com/lp/open-source). | Server + MySQL + Redis + TLS; endpoint permissions остаются у osquery. Linux возможен, но новые сетевые сервисы, credentials, updates и device-management capabilities. Высокая интеграционная стоимость. [Architecture](https://fleetdm.com/docs/deploy/reference-architectures). | Заменяет fleet inventory/UI/расписания, но для одного локального устройства **DEFER**. |
| **Wazuh**: актуальная XDR/SIEM документация; GPLv2/Apache-2.0 по компонентам. [Quickstart](https://documentation.wazuh.com/current/quickstart.html). | Agent + server + indexer + dashboard; quickstart для 1–25 agents рекомендует 4 vCPU/8 GiB/50 GB. Agent visibility/active response требуют отдельного privilege review. Linux поддержан; Pop не объявляем сертифицированным. | Заменяет большую часть collectors/FIM/rules/UI, но эксплуатационная цена чрезмерна. **DEFER**, active response не включать. |
| **Falco**: maintained CNCF runtime detection, документация обновлялась в 2026; Apache-2.0. [Packages](https://falco.org/docs/setup/packages/), [license](https://raw.githubusercontent.com/falcosecurity/falco/master/LICENSE). | Kernel events, eBPF/capabilities или module; затраты зависят от event rate/rules/buffers. DEB-инсталляция может включить services; ядро Pop/доступность probe надо проверять. [Privileges](https://falco.org/docs/concepts/event-sources/kernel/). | Заменяет будущий syscall runtime detector, не snapshot/config review. **DEFER** до потребности в event detection. |
| **Lynis**: GPLv3; upstream release 3.1.6 и разработка 3.1.8 pre-release в июле 2026. [Project](https://github.com/CISOfy/lynis), [development metadata](https://github.com/CISOfy/lynis/blob/master/lynis). | Периодический audit без resident daemon; full audit обычно root, non-root coverage ограничен; I/O и subprocess burst. Linux/Ubuntu подходит как кандидат, не доказательство applicability каждого finding на Pop. Reports по умолчанию пишутся вне проекта. [Usage](https://cisofy.com/documentation/lynis/). | Готовый периодический host audit вместо своей библиотеки hardening checks. **WRAP** отчёт по отдельному запросу, не ежедневный обязательный сервис. |
| **OpenSCAP + ComplianceAsCode**: engine LGPL-2.1; видимый release 1.4.4, 09.04.2026; отдельный maintained content project. [Engine](https://github.com/OpenSCAP/openscap), [content](https://github.com/ComplianceAsCode/content). | XCCDF/OVAL/probes, права зависят от проверок; full profile может быть тяжёлым. Наличие Ubuntu content не доказывает Pop CPE/profile applicability. Tailoring, XML и обновление content дороже Lynis; remediation недопустима автоматически. | Compliance engine вместо собственного compliance; **DEFER**, пока нет конкретного стандарта. |
| **Docker Bench**: Apache-2.0; последний видимый release 1.6.1 от 20.12.2023, README привязан к CIS 1.6.0. [Repository](https://github.com/docker/docker-bench-security). | Batch shell audit, JSON, выбор check IDs; широкий host/rootful доступ. Upstream предупреждает, что опубликованный image устарел. Нужны review выбранных checks, совместимость Engine 29, ограничение stdout/logs и минимизация. Не запускать рекомендованный privileged container автоматически. [README](https://raw.githubusercontent.com/docker/docker-bench-security/master/README.md). | Повторно использовать для CIS-аудита, **не выбирать автоматической заменой** bounded capture. Старый release не доказывает заброшенность, но мешает считать готовую поставку проверенной на новом Engine. |
| **Trivy**: Apache-2.0; продолжающиеся releases и advisories 2026. [Releases](https://github.com/aquasecurity/trivy/releases), [license](https://raw.githubusercontent.com/aquasecurity/trivy/main/LICENSE). | CLI, существенные scan/cache/DB bursts, без постоянного server. Для выбранного repo/архива root/socket не нужен; source selection и сеть задавать явно, не наследовать registry credentials. Сканирование Ubuntu packages не гарантирует coverage Pop-specific packages. | Предпочтительный единый vuln+IaC scanner после проверки происхождения конкретного release; **WRAP**. Не подключать broad secret scan поверх Gitleaks без причины. |
| **Gitleaks**: MIT, upstream объявил feature-complete/security-patches-only; это не прежняя модель активного feature development. [Project](https://github.com/gitleaks/gitleaks). **Betterleaks**: MIT, новый активный преемник; равная эксплуатационная зрелость пока не доказана. [Project](https://github.com/betterleaks/betterleaks). | Linux CLI от обычного UID; сканирует реальные secrets в памяти. CPU/I/O зависит от history, выбранных paths, архивов. Есть JSON/SARIF/redaction/timeout; не выводить raw finding или report целиком. Проверять результаты redaction отдельно от metadata projection. [Gitleaks flags](https://raw.githubusercontent.com/gitleaks/gitleaks/master/README.md). | Gitleaks — консервативный первый adapter; перед pin проверить продолжение security support. Betterleaks — резерв, не автоматическая миграция по новизне. |
| **Syft / Grype**: Apache-2.0, продолжающиеся releases Anchore. [Syft](https://github.com/anchore/syft/releases), [Grype](https://github.com/anchore/grype/releases). | Linux CLI, selected files/image archive/SBOM без root; DB download и parsing — отдельная граница. Нагрузка зависит от catalog/DB; минимизировать file/package metadata. Syft создаёт SBOM, Grype сопоставляет CVEs; Grype не требует установки второго CLI для обычного scan. [Syft scope](https://raw.githubusercontent.com/anchore/syft/main/README.md), [Grype scope](https://raw.githubusercontent.com/anchore/grype/main/README.md). | Grype — **альтернатива** Trivy для CVE-only; Syft только для отдельного SBOM workflow. Не добавлять весь набор. |
| **Sigma / engines**: SigmaHQ rules DRL-1.1, pySigma LGPL-2.1. [Licenses](https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE), [pySigma](https://github.com/SigmaHQ/pySigma). | Rules/translation не дают telemetry. pySigma — converter, не готовый evaluator нашего JSON. `sigma-go` MIT — evaluator library, оставляет pipeline/aggregation разработчику; Chainsaw ориентирован на Windows artefacts. [sigma-go](https://github.com/bradleyjkemp/sigma-go), [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw). | Не писать engine. **DEFER** до реальной log source/schema; текущие object diffs не требуют Sigma. |
| **OpenCTI / MISP**: maintained CTI platforms; OpenCTI CE Apache-2.0/EE отдельно, MISP AGPLv3. [OpenCTI](https://raw.githubusercontent.com/OpenCTI-Platform/opencti/master/README.md), [MISP](https://raw.githubusercontent.com/MISP/MISP/2.5/README.md). | Web/services, accounts, threat-feed/sharing governance. OpenCTI использует Elasticsearch/Redis/S3/RabbitMQ; тяжёлый footprint и высокая стоимость интеграции, даже если Linux deployment возможен. [Architecture](https://docs.opencti.io/latest/deployment/overview/). | Ничего необходимого текущему personal drift monitor. **DEFER**, дальнейший детальный sizing не влияет на решение. |
| **AIDE**: GPL-2.0, stable 0.19.4 от 30.08.2026, Ubuntu packages. [Upstream](https://aide.github.io/). | Batch FIM, собственная reference DB; root нужен для закрытых файлов, не для всех запусков. Цена — filesystem I/O/размер manifest; restrict paths, review DB updates. Потребуется mapping changes в наш contract. | Предпочтительнее собственного широкого FIM. **DEFER** установки: для нескольких файлов дополнительная DB не окупается. |
| **systemd/journald/Linux interfaces**: штатный поддерживаемый слой дистрибутива; systemd преимущественно LGPL-2.1+, лицензии отдельных файлов различаются. [Upstream](https://systemd.io/). | User timers без root-daemon проекта; journald уже хранит journal. Затраты зависят от jobs. Сверять flags с установленной версией, не слепо с latest. [Timer v249](https://raw.githubusercontent.com/systemd/systemd/v249/man/systemd.timer.xml), [journalctl v249](https://raw.githubusercontent.com/systemd/systemd/v249/man/journalctl.xml). | **REPLACE** наши scheduling loops при переходе к ежедневной эксплуатации; сохранять one-shot operations и контроль kill switch. Не добавлять Celery/APScheduler/workflow engine. |
| **Cockpit**: maintained Linux admin UI; преимущественно LGPL-2.1+, mixed assets/licenses. [Project](https://github.com/cockpit-project/cockpit). | Socket-activated web/admin surface, PAM/authorization и доступ к управлению ОС; Ubuntu packaging есть. Дополнительный HTTP service ради read-only evidence не оправдан. [Deployment](https://cockpit-project.org/running.html). | Готовый OS dashboard, но не privacy/approval UX нашего проекта. **DEFER**; в минимальной архитектуре достаточно CLI. |

### Почему osquery — pilot, а не немедленный общий rewrite

`listening_ports` содержит protocol/family/address/pid/fd/socket, в Linux namespace.
Это подходящая замена разбора `ss`, но не доказательство того же покрытия связанных
UDP sockets и недоступных владельцев. [Schema](https://raw.githubusercontent.com/osquery/osquery/master/specs/listening_ports.table).
Accounts имеют local scope и отдельные membership tables; remote/LDAP scope не
включать. [Users](https://raw.githubusercontent.com/osquery/osquery/5.23.1/specs/users.table),
[groups](https://raw.githubusercontent.com/osquery/osquery/5.23.1/specs/groups.table),
[membership](https://raw.githubusercontent.com/osquery/osquery/5.23.1/specs/user_groups.table).

В `systemd_units` вызывается `ListUnits`; ошибки соединения/вызова возвращают пустые
rows с diagnostic log, ошибки properties не превращаются в полноценный coverage
contract. Это не `ListUnitFiles` и не fingerprint всех drop-ins. Поэтому один
успешный SQL/JSON transport нельзя превращать в `status=ok` для прежнего scope.
[Schema](https://raw.githubusercontent.com/osquery/osquery/master/specs/linux/systemd_units.table),
[implementation](https://raw.githubusercontent.com/osquery/osquery/master/osquery/tables/system/linux/systemd_units.cpp).

### Почему не заменить весь M3 на Trivy

Trivy IaC/image-config checks не наблюдают текущие runtime HostConfig/publications.
В coverage Dockerfile поддерживается; Compose в проверенной таблице помечен `-`.
Нельзя обещать замену capture, дописав собственный Rego engine вокруг Trivy.
[IaC](https://trivy.dev/docs/latest/scanner/misconfiguration/),
[image config](https://trivy.dev/docs/latest/target/container_image/),
[Docker coverage](https://trivy.dev/docs/latest/guide/coverage/iac/docker/).

Supply-chain incident Trivy марта 2026 подтверждён upstream: затронуты binary
0.69.4, часть DockerHub images и Action tags. Это причина проверять provenance,
а не навсегда запрещать инструмент или делать собственный scanner.
[Incident](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23).
Позднее исправлены archive OOM в 0.71.0, downloaded-artifact path traversal в
0.71.1 и plugin path traversal в 0.72.0. Эти номера — границы конкретных fixes,
**не выбранные здесь безопасные версии**. Перед установкой проверить все актуальные
advisories и происхождение выбранного binary/DB; плагины не нужны.
[OOM](https://github.com/aquasecurity/trivy/security/advisories/GHSA-q3fv-x8vg-qqm4),
[download](https://github.com/aquasecurity/trivy/security/advisories/GHSA-mcj4-mphf-j9ff),
[plugins](https://github.com/aquasecurity/trivy/security/advisories/GHSA-8rc5-4fr6-64pw).

## Минимальная целевая архитектура

```text
Ручной запуск / один systemd user timer
             ↓
Готовый источник или scanner (фиксированные scope/argv/SQL)
             ↓
Маленький adapter: bounds → проверка версии/status → minimize → provenance
             ↓
SQLite: выбранное evidence + reviewed baseline + решения/исключения
             ↓
CLI: изменения, причины, ограничения, действие человека
             ↓ только явный запрос
Privacy preview → bounded AI explanation → deterministic fallback
```

Новые adapters добавляются по одному. Сначала Gitleaks для выбранного repository;
затем короткий osquery pilot для замены наиболее хрупкой части M2a. Trivy/Grype —
когда появляется конкретный image/dependency scan. Docker automation для трёх
старых неиспользуемых containers сейчас не нужна. Lynis — периодический отдельный
audit по запросу. Fleet/Wazuh/Falco/CTI, новый dashboard и event workflow не входят.

Сохранять vendor finding ID, tool/rules/DB versions, время и выбранный scope;
отделять scanner findings exit code от transport failure, skipped от PASS.
Бюджеты/минимизация не ограничивают полномочия процесса: permissions и OS isolation
проверяются отдельно, установок и host settings это решение не разрешает.
Никаких inherited scanner configs/plugins, arbitrary SQL из LLM, `SELECT *`,
raw reports/secret snippets в evidence packs или автоматического fix/update baseline.

## Стоимость и порядок миграции

Оценки ниже — инженерные ориентиры для одного разработчика, не обещанный срок.

| Шаг | Что меняется и что удаляется | Данные/tests/стоимость |
| --- | --- | --- |
| Первое сокращение — сейчас | Удалить synthetic Docker store/replay, `docker-demo`, `docker-view`, UI `--docker-state`, `/api/docker*`, synthetic экран и неиспользуемый drift/context. Fixture перенести в tests. | Нет DB migration и новых dependencies. Сохранить projection/acquisition/review tests; убрать проверки удалённого store/UI. Небольшая независимая правка, менее дня. |
| Первый scanner | Fixed Gitleaks report adapter, отдельные scope и redaction; не писать detector. | Ориентир 1–2 дня после выбора/разрешения binary. До admission достаточно минимизированного локального результата; не менять main schema ради scaffolding. |
| osquery pilot → замена | Один выбранный source, equivalence matrix, minimum columns, measured overhead. Удалить заменённый parser вместе с provider-specific tests только после успешной проверки. | Pilot 0,5–1 день; production adapter 1–3 дня при совпадении scope. Нет совпадения — оставить штатный `ss`/systemd adapter и записать конкретный gap, не строить osquery extensions. |
| Ежедневное расписание | Один user timer и oneshot scan; затем убрать дубли Python scheduling. | Ориентир 0,5–1 день плюс согласование unit installation. Проверить overlap, persistent catch-up, disabled flag, nonzero partial exits и resource limits. Не использовать timer как доказательство event recovery. |
| Journal/UI/AI timeline | Не расширять legacy M2c. Удалять producer/HTTP только отдельным небольшим переходом с сохранением reader и принятого UX, если он всё ещё нужен. | Не тратить время на новые acceptance сценарии замороженных функций. Сохранить существующие regression tests, пока команды поставляются. Не объединять БД ради эстетики. |

При смене collector сохраняются общие safety contracts, а не обязательно прежние
fingerprints: новый provider/version/scope требует нового reviewed baseline.
Не выдавать `ss` и osquery inventory за один и тот же источник при разных omissions.
Не переносить active trust на другой finding ID/контекст автоматически. Для нового
scanner source потребуется явный admission/version change: текущий `SOURCES` закрыт,
произвольный scanner report уже сегодня нельзя просто записать в M2a snapshots.

Удалённая synthetic DB не содержала host observations, её не импортировать в main DB.
Оставшиеся файлы evidence не удаляются. Для воспроизведения старого demo доступен
исходный commit `2046f65`; это историческая воспроизводимость, не production reader.
M2a trial DB v2, M2c sidecar v1, E01–E16, прежние ADR и результаты acceptance сохраняют
первоначальный provenance. После смены поставляемого scope новый trial измеряет
новую конфигурацию; старый PASS не переносится на другой backend.

## Сохранённое evidence незавершённого M3

До запроса аудита выполнены три разрешённых host capture и локальная проверка.
Во время аудита повторного acquisition нет. `/usr/bin/time` измерял всю команду
`uv run --cache-dir .cache/uv --no-sync sec docker-acquire ...`; код collector не менялся.

[Publication redaction: private workstation observation/configuration omitted.]



SHA-256 `capture.json` по порядку:

```text
af96c326b7fc9104f08de76a2efdfa562eb0cbada020a945a181b64974886b15
dea80070a68b5d3e268cf83a98ad6ffc72fb31d28bba988f1256f3345fc3f596
fdc6fb0fac7978c3eafe7f26bb3963696e941fe40985b4b06fb5d7e0bd9dd72b
```

Три раза exit 0, `artifact_valid=true`, status ok, Engine 29.1.3, 3 stopped containers,
unknown fields/inspect failures 0, lists/socket consistent. Нормализованные records,
source reference и findings равны между собой и прежнему capture
`m3-host-20260913-r3`; полные файлы различаются timestamps/approval token.
Каждый capture 3071 bytes, mode 0600, каталоги 0700, client-config пуст.
Повтор existing output, token от другого пути и неверный digest отвергнуты с exit 2
до нового сбора. Это выполнено до переключения на аудит; partial/daemon failure
не провоцировались и не объявляются пройденными на хосте.

[Publication redaction: private workstation observation/configuration omitted.]



## Проверка поставки

Проверяются только изменения удаления и их зависимости: CLI dispatch, общие queries,
HTTP/DOM, Docker projection/offline review и отсутствие regression M2a/M2b/M2c.
Никаких новых host collectors, scanner downloads, services, firewall, baseline updates
или inference в рамках аудита.

Результаты: **237 synthetic unittest PASS** (9,083 s), Ruff, repository hygiene,
UI DOM — PASS. Ранее было 250 tests; удалены 14 tests исключённой feature и добавлен
один regression на отказ retired Docker API до чтения evidence. Отдельно проверен
отказ `docker-demo`, `docker-view`, `ui --docker-state` до открытия Store.
Повторный host scan, browser listener и fault injection не выполнялись.
Offline wheel/sdist inspection — PASS: по 43 regular files, точный состав
source/assets/metadata; удалённые модули, test fixtures и runtime evidence в package
не попали. Проверены 82 локальные ссылки, `git diff --check` — PASS. Dependency/lock
changes нет. Сохранённый `m3-perf-20260913-r3/capture.json` после сокращения прошёл
offline review с прежним digest, без повторного acquisition.
