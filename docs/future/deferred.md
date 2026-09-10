# Отложенные направления

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-10. Статус: контекст и ограничения; не текущие задачи.
Приоритеты и момент реализации определяет [roadmap](../ROADMAP.md).

## Windows и другие Linux hosts

Сейчас переносимы модели данных и detection core, не сенсоры. OS-specific paths,
service management и collection — adapters. Не строить enrollment, central server,
tenant isolation или distributed transport заранее. Возможная будущая коммерческая
услуга не требует этих компонентов в личном продукте сегодня.

## IoT / Grow System (прежний M6)

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



## Изолированный pentest lab (прежний M7)

Xiaomi Mi 9 Lite — untrusted/lab endpoint, без production credentials, основного
2FA и личных secrets. Только собственные или явно разрешённые targets в изоляции.
Цель: controlled action → telemetry → detector → explanation. Production workstation
не превращается в уязвимую мишень. Лабораторные артефакты не попадают в host baseline.

## Multi-host и интеграции (прежние M5/M8)

Дополнительные Linux hosts, home server, Telegram/Signal notifications — после
стабильного локального alert model. Минимизировать notification payloads.
Dashboard не публиковать в Internet по умолчанию. Централизованное управление и
MCP-интерфейс возможны только под конкретного потребителя и threat model;
не экспортировать произвольные system tools.

Крупные SIEM/IDS stacks, Wazuh manager, Suricata, Zeek, CrowdSec/Fail2ban, Falco
и ClamAV не являются обязательным набором. Рассматривать по изменившейся угрозе
и уникальной пользе, с оценкой overhead, конфликтов и rollback.
