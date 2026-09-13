"use strict";
(() => {
  let token = "", session = 0, navigation = 0, historyId = 0;
  let route = { page: "overview" };
  // History may survive this document. Keep even alert IDs/cursors in tab memory only.
  const routes = new Map();
  const $ = id => document.getElementById(id);
  const labels = {
    ok: "Доступен", partial: "Частичное наблюдение", unavailable: "Недоступен",
    stale: "Устарело", configuration_mismatch: "Изменилась конфигурация",
    parser_failure: "Ошибка формата", collection_limitation: "Ограничение сбора",
    current: "Актуальные наблюдения", degraded: "Есть ограничения",
    running: "Monitor работает", not_running: "Monitor не работает",
    unknown: "Состояние monitor неизвестно", continuation: "Cursor продолжен",
    first_observation: "Первое наблюдение", cursor_unavailable: "Cursor недоступен",
    cursor_invalid: "Невалидный cursor", cursor_lost: "Cursor потерян",
    rotated_beyond_cursor: "Ротация за границей cursor", access_failure: "Ошибка доступа",
    source_unavailable: "Источник недоступен", not_configured: "Journald не подключён",
    storage_or_contract_failure: "Ошибка БД или несовместимый контракт",
    never_observed: "Ещё не наблюдался", boot_boundary: "Граница перезагрузки",
    trigger: "Начало расследования", evidence_pack: "Evidence pack",
    privacy_preview: "Privacy preview", privacy_accepted: "Передача одобрена",
    privacy_rejected: "Передача отклонена", provider_request: "Запрос provider",
    provider_result: "Ответ provider", operation_request: "Запрос операции",
    operation_accepted: "Операция разрешена", operation_rejected: "Операция отклонена",
    evidence_acquired: "Получено evidence", fallback: "Детерминированное объяснение",
    stop: "Завершение", access_or_source_failure: "Диагностика journalctl: доступ или источник",
    never_collected: "Сбор ещё не выполнялся", access_or_io: "Нет доступа или ошибка чтения",
    limit: "Достигнут предел сбора", timeout: "Истёк срок сбора",
    command_failed: "Команда сбора не выполнена", missing_command: "Нет команды сбора",
    context_missing: "Контекст процесса неполон", unsupported_platform: "Платформа не поддержана",
    source_missing: "Collector не вернул источник", cancelled: "Сбор отменён",
    unknown_diagnostic: "Неизвестная причина ограничения"
  };
  const label = value => labels[value] || String(value ?? "Неизвестно");

  // All evidence and labels are text nodes, never HTML, Markdown or executable links.
  function node(tag, text, cls) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = String(text);
    if (cls) el.className = cls;
    return el;
  }
  function pretty(parent, title, value) {
    const d = node("details");
    d.append(node("summary", title), node("pre", JSON.stringify(value, null, 2)));
    parent.append(d);
  }
  async function api(path) {
    const currentSession = session;
    const currentNavigation = navigation;
    const response = await fetch(path, {
      headers: { "Authorization": "Bearer " + token, "X-Sec-UI": "1" },
      credentials: "omit", cache: "no-store", redirect: "error",
      signal: AbortSignal.timeout(7000)
    });
    if (currentSession !== session || currentNavigation !== navigation)
      throw new Error("Сессия или экран изменились; ответ отклонён.");
    if (!response.ok) {
      if (response.status === 401) {
        forget();
        error(new Error("Ключ не принят или истёк. Введите ключ заново."));
      }
      throw new Error(response.status === 401
        ? "Ключ не принят или истёк. Введите ключ заново."
        : "Запрос не выполнен. Данные не подтверждены; проверьте CLI и состояние БД.");
    }
    const data = await response.json();
    if (currentSession !== session || currentNavigation !== navigation)
      throw new Error("Сессия или экран изменились; данные не отображены.");
    return data;
  }
  function error(e) {
    $("error").textContent = e.message || "Запрос не выполнен";
    $("error").hidden = false;
  }
  function show(name) {
    ["overview", "alerts", "detail"].forEach(id => $(id).hidden = id !== name);
    $("error").hidden = true;
  }
  function stamp() {
    $("updated").textContent = "Обновлено: " + new Date().toLocaleString()
      + " · Обновление вручную · LLM из UI не запускается";
  }
  function forget() {
    session += 1;
    token = "";
    $("token").value = "";
    $("workspace").hidden = true;
    $("login").hidden = false;
    $("logout").hidden = true;
    ["overview", "alerts", "detail"].forEach(id => $(id).replaceChildren());
    $("updated").textContent = "";
    $("error").textContent = "";
    $("error").hidden = true;
    routes.clear();
    // Cleanup also runs during pagehide; do not require an active History document.
    route = { page: "overview" };
  }

  function remember(next, replace = false) {
    route = next;
    routes.set(++historyId, route);
    window.history[replace ? "replaceState" : "pushState"](historyId, "", "/");
  }
  async function render() {
    const currentSession = session, currentNavigation = ++navigation;
    if (!token) return false;
    try {
      await (route.page === "detail" ? detail(route.id)
        : route.page === "alerts" ? alerts(route.before) : overview());
      return currentSession === session && currentNavigation === navigation;
    } catch (e) {
      if (currentSession === session && currentNavigation === navigation) error(e);
      return false;
    }
  }
  function navigate(next) {
    if (!token) return;
    if (route.page !== next.page || route.id !== next.id || route.before !== next.before)
      remember(next);
    return render();
  }

  async function overview() {
    show("overview");
    const data = await api("/api/overview"), panel = $("overview");
    panel.replaceChildren(node("h1", "Состояние наблюдения"));
    panel.append(node("p", label(data.monitor) + (data.disabled
      ? " · Monitoring выключен" : " · Monitoring разрешён")));
    const metrics = node("div", undefined, "metrics");
    for (const [value, title] of [
      [data.active_alerts, "Активных предупреждений"],
      [data.pending_notifications, "Ожидают уведомления"],
      [data.baseline_revision, "Ревизия baseline"],
      [Math.round(data.storage_bytes / 1024), "Хранилище, KiB"]
    ]) {
      const metric = node("div", undefined, "metric");
      metric.append(node("strong", value), node("span", title));
      metrics.append(metric);
    }
    panel.append(metrics);
    if (data.health !== "current" || data.storage_failure) {
      panel.append(node("p",
        "Наблюдение ограничено. Недоступные данные не означают, что изменений не было.", "warning"));
    }
    panel.append(node("h2", "Источники"));
    const grid = node("div", undefined, "grid");
    for (const source of data.sources) {
      const card = node("div", undefined, "source");
      card.append(node("strong", source.source), node("p", label(source.status)),
        node("p", source.at || "Сбор ещё не выполнен", "muted"));
      if (source.reasons.length) card.append(node("p", source.reasons.map(label).join(" · ")));
      grid.append(card);
    }
    panel.append(grid, node("h2", "Journald и пробелы наблюдения"));
    const reliability = data.reliability;
    panel.append(node("p", label(reliability.state)));
    if (reliability.stale) panel.append(node("p",
      "Journal checkpoint устарел; новые события не подтверждены.", "warning"));
    if (reliability.storage_failure) panel.append(node("p",
      "Последняя запись reliability DB завершилась ошибкой.", "warning"));
    if (reliability.gap_count) panel.append(node("p",
      `${reliability.gap_count} пробелов в истории. Сверка текущего состояния не восстанавливает промежуточные события.`, "warning"));
    pretty(panel, "Checkpoint, gaps и последняя сверка", reliability);
    panel.append(node("h2", "Как читать эти данные"), node("p",
      "Baseline — состояние, которое вы подтвердили. Оно не доказывает чистоту хоста. Partial позволяет увидеть положительные изменения, но отсутствие объекта не доказывает его удаление."),
      node("p", `Приложение ${data.application_version} · watchdog SQLite v${data.database_version} · UI запущен локально`));
    stamp();
  }

  async function alerts(before) {
    show("alerts");
    const data = await api("/api/alerts?limit=25" + (before ? "&before=" + before : ""));
    const panel = $("alerts");
    panel.replaceChildren(node("h1", "Предупреждения"));
    if (!data.items.length) panel.append(node("p",
      "В этой странице нет предупреждений. Проверьте актуальность источников в обзоре."));
    for (const alert of data.items) {
      const row = node("div", undefined, "alert-row"), facts = node("div");
      const button = node("button", "Открыть #" + alert.id);
      button.addEventListener("click", () => navigate({ page: "detail", id: alert.id }));
      facts.append(node("strong", alert.summary), node("p",
        `${alert.source} · ${alert.status} · ${alert.active ? "активен" : "не активен"}`),
        node("span", alert.at, "muted"));
      row.append(node("span", alert.severity, "badge " + alert.severity), facts, button);
      panel.append(row);
    }
    if (data.next_before) {
      const button = node("button", "Следующая страница");
      button.addEventListener("click", () => navigate({ page: "alerts", before: data.next_before }));
      panel.append(button);
    }
    stamp();
  }

  function timeline(panel, data) {
    panel.append(node("h2", "Timeline расследования"));
    const saved = data.saved_investigation;
    if (!saved) {
      panel.append(node("p", data.investigation_storage_state === "storage_or_contract_failure"
        ? "Не удалось прочитать хранилище timeline. Это не подтверждает отсутствие расследований."
        : data.timeline_notice),
        node("p", "Доступно детерминированное объяснение выше. LLM выключен для UI."));
      return;
    }
    panel.append(node("p", saved.mode === "deterministic"
      ? "Результат: deterministic fallback" : "Результат: гипотеза AI, требуется проверка человеком"));
    const list = node("ol", undefined, "timeline");
    for (const entry of saved.entries) {
      list.append(node("li", `${entry.at} · ${label(entry.kind)} · ${entry.code}`
        + (entry.operation ? " · " + entry.operation : "")
        + (entry.references?.length ? " · " + entry.references.join(", ") : "")));
    }
    panel.append(list, node("p",
      `Шагов provider: ${saved.step_count}; причина остановки: ${saved.stop_reason}`));
    pretty(panel, "Бюджеты", saved.budgets);
    panel.append(node("p",
      "Текст provider исключён из сохранённой timeline для минимизации данных. Он не является verified fact."));
  }

  async function detail(id) {
    show("detail");
    const data = await api("/api/alerts/" + id), panel = $("detail");
    const facts = data.deterministic;
    panel.replaceChildren(node("h1", "Предупреждение #" + id));
    panel.append(node("p",
      `${facts.detector.severity} · ${facts.detector.detector_id} · ${facts.detector.source}`),
      node("h2", "Детерминированные факты"), node("p", facts.summary));
    pretty(panel, "Нормализованные observations и evidence IDs", data.evidence.alert);
    pretty(panel, "Полнота и время сбора", data.evidence.source_coverage);
    panel.append(node("h2", "Почему это важно"), node("p", facts.guidance.mechanism),
      node("p", facts.guidance.importance), node("h3", "Что проверить вручную"),
      node("p", facts.guidance.manual_check), node("h3", "Что неизвестно"),
      node("p", facts.guidance.limits), node("p",
      `Метаданные показаны с псевдонимами. Локальные оригиналы: sec explain ${id}. Отображаемые строки — данные, а не команды к исполнению.`, "warning"));
    timeline(panel, data);
    stamp();
  }

  $("key-form").addEventListener("submit", async event => {
    event.preventDefault();
    session += 1;
    token = $("token").value;
    $("token").value = "";
    remember(route, true);
    if (await render()) {
      $("login").hidden = true;
      $("workspace").hidden = false;
      $("logout").hidden = false;
    }
  });
  $("logout").addEventListener("click", forget);
  $("overview-button").addEventListener("click", () => navigate({ page: "overview" }));
  $("alerts-button").addEventListener("click", () => navigate({ page: "alerts" }));
  $("refresh").addEventListener("click", render);
  window.addEventListener("popstate", event => {
    const saved = Number.isSafeInteger(event.state) ? routes.get(event.state) : undefined;
    if (saved) route = saved;
    else remember({ page: "overview" }, true);
    return render();
  });
  window.addEventListener("pagehide", forget);
  remember(route, true);
})();
