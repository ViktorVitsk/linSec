# Первоначальный security audit

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Historical workstation audit. Observation values and actionable private findings are withheld; the original is retained privately. This public form is not a current host assessment.

## 1. Executive summary
[Publication redaction: private workstation observation/configuration omitted.]

## 2. Что и как проверено


### Безопасность сессии

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



Прочитаны `/workspace/agent-policy/AGENTS.md` и проектный `AGENTS.md`, включая доступные
родительские пути поиска инструкций. В проектном тексте ослабления глобальной
политики не обнаружены. Вне sandbox `.git` отсутствует и `git status` завершается
ошибкой: **UNKNOWN** — изменения относительно доверенного Git baseline.
В начале проекта других policy/config-файлов в доступном файловом списке не было.

Контрольные SHA-256 этого снимка, не доказательство доверенности:

[Publication redaction: native command/output block withheld.]

### Источники evidence

- E01: `id`, `ps -o pid,ppid,euid,egid,comm`, выбранные `/proc/*/status`, Git status,
  чтение инструкций и их SHA-256.
- E02: `/etc/os-release`, `/etc/lsb-release`, `uname -srmo`, `dpkg-query`,
  выбранные APT sources и локальный `apt.Cache()` без обновления индексов.
- E03: `ip -brief address`, `ip route show`, `ip -6 route show`, `ss -H -lntup`,
  `resolvectl dns`, `resolvectl default-route`, агрегированный `ss ... established`.
- E04: system/user `systemctl list-units`, `list-unit-files`, `list-timers`,
  `--failed`, `show` с фиксированными свойствами без Environment/ExecStart.
- E05: public account/group records без password fields; метаданные persistence,
  ограниченные fingerprints, число записей `crontab -l` без command contents.
- E06: `lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS`, host `findmnt -T /` и
  `findmnt -T /home/portfolio`, один data byte EFI SecureBoot/SetupMode,
  выбранные sysfs/sysctl/kernel config indicators.
- E07: только GET локального Docker Unix API: `/version`, `/info`,
  `/containers/json?all=1`, inspect конкретных найденных IDs, `/networks`,
  `/images/json`. До вывода оставлены лишь поля posture. Env values не выведены.
- E08: metadata package manifests IDE/Node/Python и Firefox `extensions.json`,
  без cookies/history/session storage. `flatpak list --app`.
- E09: whitelist полей Pop updater config, даты и package operations из
  APT history; только признаки conventional backup locations, без backup contents.

[Publication redaction: private workstation observation/configuration omitted.]



Пользователь отдельно разрешил восемь sudo diagnostics: UFW status,
iptables/ip6tables saves для nft/legacy, aa-status, ss с владельцами, visudo check.
**Все восемь не выполнились:** `sudo -n: a password is required`.
Не использовались интерактивный пароль, `sudo -v` или обход через Docker.

Не выполнялись обновления APT indices/packages, установки, vulnerability/secret scans,
сетевые probes, изменение services/firewall/Docker, browser/router login.
Сырые логи, environment dumps, private SSH keys и backup contents не сохранялись.
Внешняя документация проверена отдельно без телеметрии хоста.

## 3. Current attack surface и платформа
[Publication redaction: private workstation observation/configuration omitted.]

## 4. Network exposure
[Publication redaction: private workstation observation/configuration omitted.]

## 5. Accounts / privileges
[Publication redaction: private workstation observation/configuration omitted.]

## 6. Persistence
[Publication redaction: private workstation observation/configuration omitted.]

## 7. Packages / updates
[Publication redaction: private workstation observation/configuration omitted.]

## 8. AppArmor / boot / disk / kernel
[Publication redaction: private workstation observation/configuration omitted.]

## 9. Docker
[Publication redaction: private workstation observation/configuration omitted.]

## 10. Developer attack surface
[Publication redaction: private workstation observation/configuration omitted.]

## 11. Backup / recovery observations
[Publication redaction: private workstation observation/configuration omitted.]

## 12. Findings, по severity
[Publication redaction: private workstation observation/configuration omitted.]

### F01 — private finding details withheld

### F02 — private finding details withheld

### F03 — private finding details withheld

### F04 — private finding details withheld

### F05 — private finding details withheld

### F06 — private finding details withheld

### F07 — private finding details withheld

### F08 — private finding details withheld

### F09 — private finding details withheld

## 13. Unknowns / ограничения
[Publication redaction: private workstation observation/configuration omitted.]

## 14. Приоритетные следующие действия
[Publication redaction: private workstation observation/configuration omitted.]

