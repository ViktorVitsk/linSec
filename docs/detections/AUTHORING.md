# Как документировать детектор

Дата: 2026-09-10. Это руководство; детекторы M2a описаны в [runbook](M2A-WATCHDOG.md).
Создавать документ вместе с реализацией и synthetic tests, не пустые заготовки.

Для каждого значимого детектора описать:

- PURPOSE / THREAT — что защищает, от какого сценария.
- BEGINNER EXPLANATION / SYSTEM INTERNALS — понятный пример и механизм ОС.
- DATA SOURCE — источники, нужные права, coverage/freshness и unavailable behavior.
- DETECTION LOGIC — точное условие, версии, пороги и зависимости от baseline.
- EVIDENCE — минимальные сохраняемые поля, исключение secrets, provenance.
- SEVERITY — обоснование для этой workstation, без автоматического «атака».
- FALSE POSITIVES / SUPPRESSION — нормальные изменения, узкий context, expiry.
- EVASION / LIMITATIONS — polling gaps, incomplete access, ограничения доверия.
- INVESTIGATION / MANUAL VERIFICATION — воспроизводимые безопасные проверки.
- RESPONSE — рекомендуемое действие, approval/verification/rollback где применимо.
- REFERENCES — первоисточники, дата проверки, происхождение/license заимствованного rule.

Краткое объяснение для CLI и подробный runbook должны соответствовать версии
детектора. Evidence string не становится командой. Тесты проверяют benign/malicious
synthetic cases, неполное evidence и изменение контекста после suppression.
Runbook для инцидента дополнительно описывает preservation, containment, recovery,
credential rotation и post-incident checks; отмечает риск потери forensic evidence.
