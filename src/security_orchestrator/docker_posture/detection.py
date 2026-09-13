"""Deterministic posture rules on positive evidence; no host action recommendations as argv."""

import ipaddress

RULES = {
    "publication": (
        "medium",
        "Настроена или наблюдалась публикация порта вне явного loopback bind. Это не проверка WAN-доступности.",
    ),
    "privileged": (
        "high",
        "Privileged расширяет полномочия контейнера. Это конфигурационный риск, не доказательство компрометации.",
    ),
    "host_namespace": ("high", "Используется host namespace: часть изоляции контейнера отключена."),
    "shared_namespace": (
        "medium",
        "Namespace разделяется с другим контейнером; доверие к соседнему workload требует проверки.",
    ),
    "sensitive_mount": (
        "high",
        "Обнаружен mount чувствительной области или Docker socket. Флаг read-only mount не ограничивает команды socket API.",
    ),
    "capabilities": (
        "medium",
        "Явно добавлены Linux capabilities. Фактические полномочия процесса этим inventory не измерены.",
    ),
    "root_user": (
        "medium",
        "Пользователь контейнера по умолчанию или явно root. Это не доказывает UID 0 на хосте: user namespaces/rootless здесь не проверены.",
    ),
    "unknown_user": ("info", "Указано имя пользователя; его UID внутри image неизвестен."),
}


def posture(item: dict) -> list[tuple[str, dict]]:
    found = []
    exposed = {}
    for field in ("configured_ports", "observed_ports"):
        risky = [
            p
            for p in item[field] or []
            if not p["ip"] or not ipaddress.ip_address(p["ip"]).is_loopback
        ]
        if risky:
            exposed[field] = risky
    if exposed:
        found.append(("publication", exposed))
    if item["privileged"] is True:
        found.append(("privileged", {"privileged": True}))
    for rule, mode in (("host_namespace", "host"), ("shared_namespace", "container")):
        fields = {k: item[k] for k in ("network", "pid", "ipc", "uts", "userns") if item[k] == mode}
        if fields:
            found.append((rule, fields))
    sensitive = [m for m in item["mounts"] or [] if m["class"] != "other"]
    if sensitive:
        found.append(("sensitive_mount", {"mounts": sensitive}))
    if item["cap_add"]:
        found.append(("capabilities", {"cap_add": item["cap_add"], "cap_drop": item["cap_drop"]}))
    if item["user"] in {"default_root", "explicit_root"}:
        found.append(("root_user", {"user": item["user"]}))
    elif item["user"] == "named_unknown":
        found.append(("unknown_user", {"user": item["user"]}))
    return found
