"""Deterministic Russian explanations; no generated commands or AI calls."""

from .application import Application


GUIDANCE = {
    "endpoint": {
        "mechanism": "Процесс привязал сокет к адресу и порту. TCP LISTEN принимает соединения; UDP bind не равен TCP listener.",
        "importance": "Новый bind или другой executable/user может расширить доступ к сервису. Wildcard не доказывает доступ из WAN.",
        "normal_causes": "Запуск приложения, обновление, смена адреса интерфейса или временный UDP-клиент.",
        "manual_check": "Сравните sec explain с выводом ss -H -O -n -l -t -e -p и ss -H -O -n -a -u -e -p. Проверьте владельца процесса и назначение приложения.",
        "limits": "Только текущий network namespace; polling пропускает короткие события. Недоступный process context не разрешает trust/suppression. Путь executable не доказывает целостность бинарника.",
    },
    "unit": {
        "mechanism": "systemd хранит определения services/timers и отдельное состояние их включения.",
        "importance": "Новый или включённый unit может закреплять запуск программы. Изменение не доказывает атаку.",
        "normal_causes": "Обновление пакета, установка приложения, осознанное изменение enablement.",
        "manual_check": "Сверьте systemctl --system list-unit-files --type=service --type=timer и аналогичную команду с --user. Отдельно проверьте происхождение unit и drop-ins локально; не публикуйте их содержимое.",
        "limits": "Нет root; стандартные пути и доступный scope. Это inventory файлов и enablement, не доказательство текущего исполнения или эффективной конфигурации менеджера.",
    },
    "file": {
        "mechanism": "Отпечаток SHA-256 и metadata замечают изменение содержимого, прав, владельца или ссылки выбранного файла.",
        "importance": "Unit/drop-in или файл persistence способен изменить будущий запуск программы без появления нового имени файла.",
        "normal_causes": "Обновление пакета или согласованное редактирование настроек.",
        "manual_check": "Сверьте путь, владельца, права и SHA-256 локальными stat и sha256sum для проверенного пути. Для symlink проверьте также ссылку. Не вставляйте строку evidence как shell-команду и не отправляйте содержимое файла в облако.",
        "limits": "Явный список persistence и стандартные systemd paths. Полный обход диска отсутствует. SHA-256 выявляет изменение, но не оценивает безопасность содержимого.",
    },
    "uid0": {
        "mechanism": "В Linux UID 0 имеет полномочия суперпользователя независимо от имени учётной записи.",
        "importance": "Новая запись UID 0 заслуживает проверки как возможный дополнительный привилегированный вход.",
        "normal_causes": "Редкая осознанная административная настройка или изменение пакета/образа.",
        "manual_check": "Локально проверьте только name/UID/GID записей /etc/passwd и историю согласованных изменений. Не читайте /etc/shadow и не публикуйте полные account files.",
        "limits": "Только локальные /etc/passwd и /etc/group; LDAP/NSS, capabilities и sudoers здесь не покрываются.",
    },
    "group": {
        "mechanism": "Привилегии могут даваться через supplementary groups и primary GID; учитываются оба пути членства.",
        "importance": "Изменение sudo/docker/disk и других выбранных групп может открыть административные или чувствительные ресурсы.",
        "normal_causes": "Согласованная установка инструмента или изменение доступа пользователя.",
        "manual_check": "Сверьте выбранную группу в /etc/group и primary GID пользователей в /etc/passwd. Проверьте, кто и зачем согласовал доступ.",
        "limits": "Только локальные файлы и явно выбранные группы; cached credentials текущей сессии и внешние identity providers не проверяются.",
    },
}


def explain(app: Application, alert_id: int) -> dict:
    alert = app.get_alert(alert_id)
    before = app.snapshot(alert["before_id"]).get(alert["object_key"])
    after = app.snapshot(alert["after_id"]).get(alert["object_key"])
    kind = (after or before)["kind"]
    return {
        "alert": alert,
        "what_changed": alert["change_type"],
        "evidence": {
            "before_snapshot": alert["before_id"],
            "after_snapshot": alert["after_id"],
            "before": before,
            "after": after,
        },
        **GUIDANCE[kind],
        "severity_reason": "high: привилегированный доступ или wildcard bind; medium: прочий drift; info: удаление.",
        "response": "Проверьте происхождение изменения. Для ожидаемого события используйте узкое исключение с причиной или отдельный baseline diff/update. Закрытие alert не создаёт доверие.",
        "automatic_action": "Отсутствует. Настройки хоста не меняются.",
        "runbook": "docs/detections/M2A-WATCHDOG.md (детекторы версии 1)",
    }
