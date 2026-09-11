# AI-расследователь: контракт безопасности

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата решения: 2026-09-10. Статус: **требования M2b, не реализованная защита**.
Основа — [архитектура](overview.md) и [правила безопасности](../operations/safety-rules.md).
Уточнение 2026-09-11: [границы доверия перед M2b](trust-boundaries.md). Локальная
SQLite, accepted baseline и terminal escaping не делают evidence доверенным или
готовым для cloud export. Baseline — acknowledged state, не clean ground truth.

## Граница полномочий

Deterministic detection работает независимо от модели. `LLM_ENABLED=false`
сохраняет collection, detection, alerts и объяснения. `OPENROUTER_ENABLED=false`
и `AUTO_CLOUD_ESCALATION=false` — исходная политика будущего продукта.

Первый этап — один вызов модели на готовом evidence pack. Следующий — до пяти
последовательных шагов расследования, с конечными timeout, лимитами токенов/ответов
и расхода. Сохранять понятный журнал запросов и результатов без hidden chain-of-thought.
Простой ограниченный цикл предпочтительнее framework, пока измерения не требуют другого.

Разрешённый реестр операций:

- получить alert и связанные observations по существующим ID;
- сравнить evidence с конкретным baseline;
- прочитать соответствующий runbook из подготовленного локального каталога;
- запросить повторный сбор из уже разрешённого набора collectors.

Модель возвращает типизированный запрос. Прикладной policy layer валидирует schema,
ID, доступный scope, бюджет и разрешение. Повторный сбор вызывает заранее написанный
адаптер; модель не создаёт argv. Запретить произвольные shell, SQL, URL, пути,
доступ к Docker socket, чтение home и расширение полномочий через вложенные запросы.
Read-only intent не делает произвольный tool безопасным.

AI не закрывает alerts, не создаёт trust/suppression и не меняет baseline/host policy.
Пока нет автоматической remediation; будущие изменения системы — отдельные
типизированные действия с preview, одобрением, verification и rollback.

## Evidence и ответ

Pack содержит минимальные структурированные факты, IDs, provenance, timestamps,
trusted detector metadata и явно отделённые untrusted strings. Не направлять raw
journal, environment, private keys, tokens, cookies, browser/session stores,
произвольные исходники или содержимое домашнего каталога.

Pipeline: normalize → minimize → pseudonymize → redact → privacy validation.
Редакция по regex сама по себе не гарантирует удаления secrets; исходный набор
полей должен быть allowlisted. Runtime debug/error logging проходит те же ограничения.

Ответ: краткое объяснение, гипотезы, неизвестное, рекомендованные проверки,
evidence references. Проверять существование и принадлежность references текущему
расследованию. Валидный JSON не гарантирует истинность вывода. Серьёзность и вывод
детектора не перезаписываются оценкой AI; числовая уверенность модели не считается
калиброванной вероятностью атаки. Отказ/невалидный ответ возвращает deterministic fallback.

Prompt injection в unit description, process name, log text и другом evidence —
данные. Защита обеспечивается отсутствием полномочий и валидацией операций, а не
одной инструкцией в prompt. Generated tool arguments также untrusted.

## Провайдеры и облачный запрос

Первый cloud adapter — OpenRouter. Каждый запуск только по явному запросу владельца,
после preview минимизированного пакета и выбора конечного лимита расходов.
Повторно проверять новые evidence перед отправкой; старое согласие не разрешает
добавить новые категории данных. Без заданного бюджета или privacy check не отправлять.
Локальная ошибка не запускает cloud fallback автоматически.

Provider/model/endpoint задаются конфигурацией; проверять конкретные capabilities
(structured output, tools, context size), а не узнаваемое имя модели. Для облака
явно ограничить допустимые providers и privacy routing, не ослаблять ограничения
ради fallback. Credentials вне Git; не хранить их в analysis records.

[Publication redaction: private workstation observation/configuration omitted.]



## Проверка новых LLM/SLM

Версионированный набор синтетических сценариев: benign change, подтверждённая
аномалия, недостаточные/устаревшие данные, конфликт evidence, injection, выдуманный
ID, запрещённый tool, повторные запросы и исчерпание бюджета.

Для каждой модели записывать prompt/schema/provider/model versions, корректность
ссылок, неподтверждённые утверждения, качество русского объяснения, число шагов,
задержку, стоимость и локальные ресурсы. Проверка человеком важнее оценки другой LLM.
Новая модель включается после сравнения на одном наборе; runtime может оставаться
без AI, если ни один кандидат не проходит минимальные требования.

## Проверенные первоисточники

Проверка: 2026-09-10; перед интеграцией повторно проверить поддержку endpoint/runtime.

- [Anthropic: простые agent patterns](https://www.anthropic.com/engineering/building-effective-agents).
- [Ollama: structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
  и [tool calling](https://docs.ollama.com/capabilities/tool-calling).
- [OpenRouter: structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs)
  и [provider/privacy routing](https://openrouter.ai/docs/guides/routing/provider-selection).
