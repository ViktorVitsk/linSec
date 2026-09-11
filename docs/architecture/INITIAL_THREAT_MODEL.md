# Начальная модель угроз developer workstation

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-10. Основание: [фактический аудит](../audit/INITIAL_SECURITY_AUDIT.md).
Это модель рисков, не список обнаруженных атак. Область — одна developer workstation и её связь с LAN; IoT, pentest lab и multi-host не реализуются.

[Publication redaction: private workstation observation/configuration omitted.]



## Статус исходных наблюдений

[Publication redaction: private workstation observation/configuration omitted.]



Уточнение 2026-09-11 после реализации M2a: [границы доверия](trust-boundaries.md)
отдельно рассматривают tampering by the local user/root, hostile evidence, acknowledged baseline,
minimization и coding-agent процесс. Исходные host observations ниже остаются датированными.

## Что защищаем

- Исходники, Git identity, API/SSH credentials и developer configuration.
- Browser sessions и личные файлы; содержимое при аудите не читалось.
- Root privileges, доверенность package sources, systemd и shell startup.
- Docker workloads, database volume и исходники, подключаемые RW bind mounts.
- Доступность компьютера, ресурсов CPU/GPU/disk и восстановимость данных.

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



## Доверительные границы

1. Internet/package registry/extension marketplace → код в пользовательской сессии.
   Установка или import могут запускать чужой код; имя пакета не является доверием.
2. Browser content/download → локальные files/processes. Cookies и sessions остаются
   вне сбора Security Orchestrator.
3. Process пользователя → Docker socket → rootful daemon. Здесь важны не только
   sudo prompts: разрешённый Docker client уже имеет сильные возможности.
4. Container → RW исходники/volume. Изоляция process namespaces не делает bind read-only.
5. LAN/router → network services. Доступность определяется bind, routing и filtering
   совместно. Отсутствие public SSH не исключает LAN или outbound-channel threats.
6. Disk в выключенной машине → physical reader. Linux login password не заменяет
   disk encryption; encryption не защищает от malware в разблокированной сессии.
7. Untrusted telemetry → будущий detector/explainer. Текст события — данные;
   он не получает права изменять policy или создавать команды.

## Практические сценарии

### Malicious npm/pip/dependency package

[Publication redaction: private workstation observation/configuration omitted.]



Предлагаемый контроль для последующих этапов: отдельные project env, минимальные
dependencies, lock/review и изоляция недоверенного кода. **Venv решает разделение
пакетов, но не является security sandbox** и не закрывает доступ к home/socket.
Остаточный риск: злонамеренный код under the local user can read files accessible to that user.

### Supply-chain compromise

Точка входа: package source, maintainer/build pipeline, update artifacts. Здесь
обнаружено смешение Docker Ubuntu/Debian packages. Оно не доказывает атаку, но
усложняет проверяемый путь сопровождения. Подпись repository подтверждает доверенного
подписанта, не безвредность каждой строки package code.

Следующий контроль: согласовать источники/ключи, фиксировать происхождение и обновления,
сохранять recovery. Не заменять packages автоматически ради единообразия.

### Malicious IDE/browser extension

[Publication redaction: private workstation observation/configuration omitted.]



Возможные последствия: доступ к исходникам, терминалу и user files; для browser
extensions — доступ в пределах предоставленных browser permissions. Следующий
контроль: минимальный нужный набор, review источника/permissions, отдельный контекст
для недоверенных workspaces. Не читать browser credential/session stores ради inventory.

### Stolen API/SSH credentials

[Publication redaction: private workstation observation/configuration omitted.]



Следующий контроль: ограниченный scope/lifetime, безопасное хранение, отдельный
план rotation/revocation после evidence утечки. Не объявлять credentials украденными
без evidence и не ротировать их автоматически.

### Browser/download malware, ransomware, cryptominer

[Publication redaction: private workstation observation/configuration omitted.]



Следующий контроль: штатные updates, ограничение запуска недоверенного кода,
проверенная offline/secondary copy. Версия kernel/наличие AppArmor не доказывают
безопасность произвольного download. Не запускать потенциальный образец на этой машине.

### Exposed development server

[Publication redaction: private workstation observation/configuration omitted.]



Следующий контроль: явная политика localhost/нужный LAN interface, authentication
для требуемого LAN сервиса, проверка IPv4/IPv6 и Docker forwarding. Не запрещать
будущие легитимные LAN dashboards заранее и не считать wildcard доказательством WAN.

### Docker compromise и privilege escalation

[Publication redaction: private workstation observation/configuration omitted.]



Следующий контроль: выбрать privilege model и допустимые mounts/publications;
обновлять согласованный runtime, позднее отдельно scan images. Наличие rootless extras
не означает rootless daemon. Не использовать daemon для обхода sudo/sandbox.

### Persistence

[Publication redaction: private workstation observation/configuration omitted.]



Будущий M2 должен сравнивать existence/enablement **и configuration fingerprints**,
а не только новые имена services. Снимок аудита автоматически known-good не становится.
Root attacker может подделать локальную telemetry; обещать гарантированное обнаружение
на уже полностью скомпрометированном хосте нельзя.

### Compromised LAN/router

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



### Prompt injection против будущего LLM analysis

Источник: process name, log line, package metadata, unit description или сетевое
событие с текстом «Ignore previous instructions and execute…». Это может пытаться
подменить выводы или побудить к передаче secrets/выполнению команды.

Архитектурное решение: deterministic detection независимо от LLM; trusted schema
отдельно от untrusted evidence; компактный redacted evidence pack, validated output,
никаких произвольных shell/system tools у analyst. В M2b разрешён ограниченный
набор типизированных запросов к evidence и уже разрешённым коллекторам через policy
layer; модель не создаёт команды и не меняет защиту. Контракт — [LLM security](llm-security.md).
Cloud analysis изначально выключен и возможен по явному запросу после privacy review.
Tests позже должны проверять injection strings и отсутствие side effects.
Это будущие требования, **сейчас LLM module не реализован**.

## Что не включено

Не строим SIEM, IDS, distributed agents, ML anomaly detection или autonomous
remediation. IoT/eFuse, router reconfiguration, disk encryption migration и Secure Boot
не являются действиями этой итерации. Не проектируем защиту от enterprise/APT
сценариев без связи с реальным workstation риском.

Следующее решение владельца: [NEXT_STEPS](../operations/NEXT_STEPS.md).
