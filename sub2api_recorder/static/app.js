"use strict";

function isEmbeddedPage() {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

document.documentElement.classList.toggle("is-embedded", isEmbeddedPage());

const auditBase = window.location.pathname.startsWith("/admin/audit/")
  ? "/admin/audit"
  : "/audit";
const form = document.querySelector("#filters");
const rows = document.querySelector("#rows");
const statusNode = document.querySelector("#status");
const statusText = document.querySelector("#status-text");
const resultSummary = document.querySelector("#result-summary");
const moreButton = document.querySelector("#more");
const refreshButton = document.querySelector("#refresh");
const submitButton = document.querySelector("#submit-filter");
const resetButton = document.querySelector("#reset-filters");
const emptyResetButton = document.querySelector("#empty-reset");
const emptyState = document.querySelector("#empty-state");
const errorBanner = document.querySelector("#error-banner");
const errorMessage = document.querySelector("#error-message");
const activeFilterSummary = document.querySelector("#active-filter-summary");
const rangeButtons = [...document.querySelectorAll("[data-range]")];
const startInput = document.querySelector("#start");
const endInput = document.querySelector("#end");
const timezoneLabel = document.querySelector("#timezone-label");
const viewerLabel = document.querySelector("#viewer-label");
const scopeLabel = document.querySelector("#scope-label");
const usernameFilterField = document.querySelector("#username-filter-field");
const auditPreferenceControl = document.querySelector("#audit-preference-control");
const auditPreferenceToggle = document.querySelector("#audit-enabled");
const auditPreferenceNote = document.querySelector("#audit-preference-note");
const auditDisabledNotice = document.querySelector("#audit-disabled-notice");

const metricCount = document.querySelector("#metric-count");
const metricCountNote = document.querySelector("#metric-count-note");
const metricBytes = document.querySelector("#metric-bytes");
const metricValid = document.querySelector("#metric-valid");
const metricValidNote = document.querySelector("#metric-valid-note");
const metricRange = document.querySelector("#metric-range");
const metricRangeNote = document.querySelector("#metric-range-note");

const detailDialog = document.querySelector("#detail");
const detailMeta = document.querySelector("#detail-meta");
const detailBody = document.querySelector("#detail-body");
const detailBodyHeading = document.querySelector("#detail-body-heading");
const detailId = document.querySelector("#detail-id");
const detailMethod = document.querySelector("#detail-method");
const detailModel = document.querySelector("#detail-model");
const detailSize = document.querySelector("#detail-size");
const bodyRenderNote = document.querySelector("#body-render-note");
const fullBodyToggle = document.querySelector("#full-body");
const closeDetailButton = document.querySelector("#close-detail");
const copyBodyButton = document.querySelector("#copy-body");

const PRETTY_BODY_LIMIT_BYTES = 1024 * 1024;
let serviceTimezone = "Asia/Hong_Kong";
let serverClockOffsetMs = 0;
let dateFormatter;
let timeFormatter;
let dateTimeFormatter;
let inputDateFormatter;
let activeRange = "today";

let nextCursor = null;
let currentQuery = "";
let loadedItems = [];
let queryController = null;
let queryVersion = 0;
let currentDetail = null;
let activeDetailRequest = null;
let detailRequestVersion = 0;
let detailBodyText = "";

function configureTimeFormatters(timezone) {
  dateFormatter = new Intl.DateTimeFormat("zh-HK", {
    timeZone: timezone,
    month: "2-digit",
    day: "2-digit",
    year: "numeric",
  });
  timeFormatter = new Intl.DateTimeFormat("zh-HK", {
    timeZone: timezone,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  dateTimeFormatter = new Intl.DateTimeFormat("zh-HK", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  inputDateFormatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  });
}

configureTimeFormatters(serviceTimezone);

function setStatus(message, state = "ready") {
  statusText.textContent = message;
  statusNode.title = message;
  statusNode.dataset.state = state;
}

function renderAuditPreference(enabled, personalScope = true) {
  auditPreferenceToggle.checked = enabled;
  auditPreferenceNote.textContent = enabled ? "正在记录" : "已关闭";
  auditDisabledNotice.hidden = !personalScope || enabled;
}

function localInputValue(date) {
  const parts = Object.fromEntries(
    inputDateFormatter
      .formatToParts(date)
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, part.value]),
  );
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

function serviceNow() {
  return new Date(Date.now() + serverClockOffsetMs);
}

function nextCalendarDate(dateText) {
  const date = new Date(`${dateText}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function setRange(range, shouldLoad = false) {
  const end = serviceNow();
  const normalizedRange = String(range);
  if (normalizedRange === "today") {
    const today = localInputValue(end).slice(0, 10);
    startInput.value = `${today}T00:00`;
    endInput.value = `${nextCalendarDate(today)}T00:00`;
  } else {
    const hours = Number(normalizedRange);
    const start = new Date(end.getTime() - hours * 60 * 60 * 1000);
    startInput.value = localInputValue(start);
    endInput.value = localInputValue(end);
  }
  activeRange = normalizedRange;
  rangeButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.range === activeRange);
  });
  updateRangeMetric();
  if (shouldLoad) load(true);
}

function initialiseDates() {
  setRange("today");
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  const precision = index === 0 ? 0 : size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(precision)} ${units[index]}`;
}

function safeMessage(error, fallback) {
  return error instanceof Error && error.message ? error.message : fallback;
}

function createCell(label, className = "") {
  const node = document.createElement("td");
  node.dataset.label = label;
  if (className) node.className = className;
  return node;
}

function createMethodBadge(method) {
  const badge = document.createElement("span");
  badge.className = "method-badge";
  badge.dataset.method = method || "UNKNOWN";
  badge.textContent = method || "—";
  return badge;
}

function parsePresentation(status) {
  const presentations = {
    json_stream: ["JSON", ""],
    json_fallback: ["JSON", ""],
    empty: ["空请求", "is-warning"],
    binary: ["二进制", "is-warning"],
    invalid_json: ["JSON 异常", "is-error"],
  };
  return presentations[status] || [status || "未知", "is-warning"];
}

function identityParts(item) {
  const resolved = [item.key_name, item.username].filter(Boolean);
  if (resolved.length) {
    return [resolved.join(" · "), item.token_masked || "已关联身份"];
  }
  return [item.token_masked || "未识别", "无 Key / 用户关联"];
}

function renderRow(item) {
  const row = document.createElement("tr");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-label", `查看 ${item.method} ${item.uri} 请求详情`);

  const occurredAt = new Date(item.occurred_at_iso);
  const timeCell = createCell("时间", "time-cell");
  const time = document.createElement("strong");
  time.textContent = timeFormatter.format(occurredAt);
  const date = document.createElement("span");
  date.textContent = dateFormatter.format(occurredAt);
  timeCell.append(time, date);

  const requestCell = createCell("请求", "request-cell");
  const requestLine = document.createElement("div");
  requestLine.className = "request-line";
  const uri = document.createElement("span");
  uri.className = "request-uri";
  uri.textContent = item.uri || "—";
  uri.title = item.uri || "";
  requestLine.append(createMethodBadge(item.method), uri);
  const requestMeta = document.createElement("small");
  requestMeta.textContent = item.content_type || "未标记 Content-Type";
  requestCell.append(requestLine, requestMeta);

  const modelCell = createCell("模型");
  const model = document.createElement("span");
  model.className = "model-label";
  model.textContent = item.model || "未指定";
  model.title = item.model || "";
  modelCell.append(model);

  const [identity, identityHint] = identityParts(item);
  const identityCell = createCell("身份", "identity-cell");
  const identityName = document.createElement("strong");
  identityName.textContent = identity;
  const identityMeta = document.createElement("small");
  identityMeta.textContent = identityHint;
  identityCell.append(identityName, identityMeta);

  const sizeCell = createCell("大小", "size-cell");
  sizeCell.textContent = formatBytes(item.body_size);

  const statusCell = createCell("状态");
  const statusStack = document.createElement("div");
  statusStack.className = "status-stack";
  const [statusLabel, statusClass] = parsePresentation(item.parse_status);
  const statusBadge = document.createElement("span");
  statusBadge.className = `status-badge ${statusClass}`.trim();
  statusBadge.textContent = statusLabel;
  const resolver = document.createElement("small");
  resolver.textContent = `关联：${item.resolver_status || "unknown"}`;
  statusStack.append(statusBadge, resolver);
  statusCell.append(statusStack);

  const actionCell = createCell("操作");
  const arrow = document.createElement("span");
  arrow.className = "row-arrow";
  arrow.textContent = "→";
  arrow.setAttribute("aria-hidden", "true");
  actionCell.append(arrow);

  row.append(
    timeCell,
    requestCell,
    modelCell,
    identityCell,
    sizeCell,
    statusCell,
    actionCell,
  );

  const open = () => showDetail(item);
  row.addEventListener("click", open);
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open();
    }
  });
  rows.append(row);
}

function showSkeleton() {
  document.querySelector(".table-scroll").hidden = false;
  rows.replaceChildren();
  for (let rowIndex = 0; rowIndex < 6; rowIndex += 1) {
    const row = document.createElement("tr");
    row.className = "skeleton-row";
    for (let cellIndex = 0; cellIndex < 7; cellIndex += 1) {
      const cell = document.createElement("td");
      const skeleton = document.createElement("span");
      skeleton.className = `skeleton ${cellIndex % 3 === 0 ? "short" : "medium"}`;
      cell.append(skeleton);
      row.append(cell);
    }
    rows.append(row);
  }
}

function formQuery() {
  const data = new FormData(form);
  const params = new URLSearchParams();
  for (const [key, value] of data.entries()) {
    const normalized = String(value).trim();
    if (normalized) params.set(key, normalized);
  }
  return params.toString();
}

function activeFilterCount() {
  const data = new FormData(form);
  return ["model", "uri", "token", "key_name", "username"].filter(
    (key) => String(data.get(key) || "").trim(),
  ).length;
}

function updateActiveFilterSummary() {
  const count = activeFilterCount();
  activeFilterSummary.textContent = count
    ? `已启用 ${count} 个额外筛选条件`
    : "未设置额外筛选";
}

function updateRangeMetric() {
  const start = Date.parse(`${startInput.value}Z`);
  const end = Date.parse(`${endInput.value}Z`);
  const hours = (end - start) / 3_600_000;
  if (!Number.isFinite(hours) || hours <= 0) {
    metricRange.textContent = "—";
    metricRangeNote.textContent = "请检查时间范围";
    return;
  }
  if (activeRange === "today") {
    metricRange.textContent = "今天";
    metricRangeNote.textContent = `${startInput.value.slice(0, 10)} · 00:00 — 24:00`;
  } else {
    metricRange.textContent = hours <= 48
      ? `${Math.round(hours)}h`
      : `${Math.round(hours / 24)}d`;
    const startLabel = startInput.value.replace("T", " ");
    const endLabel = endInput.value.replace("T", " ");
    metricRangeNote.textContent = `${startLabel} — ${endLabel}`;
  }
}

function updateMetrics() {
  const count = loadedItems.length;
  const totalBytes = loadedItems.reduce(
    (total, item) => total + (Number(item.body_size) || 0),
    0,
  );
  const validCount = loadedItems.filter((item) =>
    String(item.parse_status || "").startsWith("json_"),
  ).length;
  const validPercent = count ? Math.round((validCount / count) * 100) : 0;

  metricCount.textContent = count.toLocaleString("zh-HK");
  metricCountNote.textContent = nextCursor ? "已加载，还有更多记录" : "当前筛选结果";
  metricBytes.textContent = formatBytes(totalBytes);
  metricValid.textContent = count ? `${validPercent}%` : "—";
  metricValidNote.textContent = count
    ? `${validCount.toLocaleString("zh-HK")} / ${count.toLocaleString("zh-HK")} 条记录`
    : "等待数据";
  updateRangeMetric();
}

function setQueryControls(loading) {
  moreButton.disabled = loading;
  refreshButton.disabled = loading;
  submitButton.disabled = loading;
}

function renderLoadedItems() {
  rows.replaceChildren();
  loadedItems.forEach(renderRow);
  emptyState.hidden = loadedItems.length !== 0;
  document.querySelector(".table-scroll").hidden = loadedItems.length === 0;
  resultSummary.textContent = loadedItems.length
    ? `已加载 ${loadedItems.length.toLocaleString("zh-HK")} 条${nextCursor ? " · 可继续加载" : " · 已到末尾"}`
    : "未找到记录";
  moreButton.hidden = !nextCursor;
  updateMetrics();
}

async function load(reset = false) {
  if (queryController && !reset) return;
  if (queryController) queryController.abort();

  const controller = new AbortController();
  const version = ++queryVersion;
  queryController = controller;
  setQueryControls(true);
  setStatus("正在查询", "loading");
  errorBanner.hidden = true;
  emptyState.hidden = true;

  if (reset) {
    loadedItems = [];
    nextCursor = null;
    currentQuery = formQuery();
    showSkeleton();
    resultSummary.textContent = "正在读取…";
  }

  try {
    const separator = currentQuery ? "&" : "";
    const cursorPart = nextCursor
      ? `${separator}cursor=${encodeURIComponent(nextCursor)}`
      : "";
    const response = await fetch(
      `${auditBase}/api/requests?${currentQuery}${cursorPart}`,
      {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      },
    );
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "查询失败");
    if (version !== queryVersion) return;

    loadedItems.push(...payload.items);
    nextCursor = payload.next_cursor;
    renderLoadedItems();
    setStatus(`已加载 ${loadedItems.length} 条`, "ready");
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return;
    if (version !== queryVersion) return;
    const message = safeMessage(error, "查询失败");
    errorMessage.textContent = message;
    errorBanner.hidden = false;
    if (reset || loadedItems.length === 0) {
      rows.replaceChildren();
      document.querySelector(".table-scroll").hidden = true;
      resultSummary.textContent = "查询未完成";
    } else {
      resultSummary.textContent = `已保留 ${loadedItems.length} 条 · 载入更多失败`;
    }
    setStatus(message, "error");
    updateMetrics();
  } finally {
    if (queryController === controller) {
      queryController = null;
      setQueryControls(false);
    }
  }
}

function addMeta(label, value) {
  const group = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = value ?? "—";
  group.append(term, description);
  detailMeta.append(group);
}

function resetDetailPresentation(item, view) {
  detailId.textContent = `#${item.month}/${item.id}`;
  detailMethod.textContent = item.method || "—";
  detailMethod.dataset.method = item.method || "UNKNOWN";
  detailModel.textContent = item.model || "未指定模型";
  detailSize.textContent = formatBytes(item.body_size);
  detailBodyHeading.textContent = `请求内容（${view === "full" ? "完整" : "精简"}，载入中）`;
  bodyRenderNote.textContent = "正在读取";
  detailBody.textContent = "正在载入请求内容…";
  detailBodyText = "";
  copyBodyButton.disabled = true;
}

async function loadDetail(month, id, view) {
  const requestKey = `${month}/${id}/${view}`;
  if (activeDetailRequest?.key === requestKey) return;
  if (activeDetailRequest) activeDetailRequest.controller.abort();

  const controller = new AbortController();
  const version = ++detailRequestVersion;
  activeDetailRequest = { key: requestKey, controller, version };
  const viewLabel = view === "full" ? "完整内容" : "精简内容";
  setStatus(`正在载入${viewLabel}`, "loading");
  detailDialog.setAttribute("aria-busy", "true");
  fullBodyToggle.disabled = true;
  resetDetailPresentation(currentDetail, view);
  if (!detailDialog.open) detailDialog.showModal();

  try {
    const url = `${auditBase}/api/requests/${encodeURIComponent(month)}/${encodeURIComponent(id)}?view=${view}`;
    const response = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "详情载入失败");
    if (
      version !== detailRequestVersion
      || currentDetail?.month !== month
      || currentDetail?.id !== id
    ) return;

    detailMeta.replaceChildren();
    addMeta("时间", `${dateTimeFormatter.format(new Date(payload.occurred_at_iso))} · ${serviceTimezone}`);
    addMeta("URI", payload.uri);
    addMeta("客户端 IP", payload.client_ip);
    addMeta("User Agent", payload.user_agent);
    addMeta("Content-Type", payload.content_type);
    const resolvedIdentity = [payload.key_name, payload.username].filter(Boolean);
    addMeta(resolvedIdentity.length ? "Key / 用户" : "Token", resolvedIdentity.length
      ? resolvedIdentity.join(" · ")
      : payload.token_masked);
    addMeta("解析 / 关联", `${payload.parse_status} / ${payload.resolver_status}`);
    addMeta("Body SHA-256", payload.body_sha256);

    detailMethod.textContent = payload.method || "—";
    detailMethod.dataset.method = payload.method || "UNKNOWN";
    detailModel.textContent = payload.model || "未指定模型";
    detailSize.textContent = `${formatBytes(payload.body_size)} · ${payload.content_type || "unknown"}`;

    const shouldPrettyPrint = view !== "full" || payload.body_size <= PRETTY_BODY_LIMIT_BYTES;
    detailBodyText = JSON.stringify(payload.body, null, shouldPrettyPrint ? 2 : 0);
    detailBody.textContent = detailBodyText;
    detailBodyHeading.textContent = `请求内容（${view === "full" ? "完整" : "精简"}）`;
    if (view === "compact") {
      const auditView = payload.body?._audit_view;
      const shown = auditView?.shown_items;
      bodyRenderNote.textContent = Number.isFinite(shown)
        ? `最近 ${shown} 项 · 已格式化`
        : "优化预览 · 已格式化";
    } else {
      bodyRenderNote.textContent = shouldPrettyPrint
        ? `${formatBytes(payload.body_size)} · 已格式化`
        : `${formatBytes(payload.body_size)} · 无缩进`;
    }
    copyBodyButton.disabled = false;
    setStatus(`已加载 ${loadedItems.length} 条`, "ready");
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return;
    if (version !== detailRequestVersion) return;
    const message = safeMessage(error, "详情载入失败");
    setStatus(message, "error");
    detailBodyHeading.textContent = "请求内容（载入失败）";
    bodyRenderNote.textContent = "请重试";
    detailBody.textContent = message;
  } finally {
    if (activeDetailRequest?.version === version) {
      activeDetailRequest = null;
      detailDialog.removeAttribute("aria-busy");
      fullBodyToggle.disabled = false;
    }
  }
}

function showDetail(item) {
  if (
    activeDetailRequest
    && currentDetail?.month === item.month
    && currentDetail?.id === item.id
  ) return;
  currentDetail = item;
  fullBodyToggle.checked = false;
  detailMeta.replaceChildren();
  loadDetail(item.month, item.id, "compact");
}

function cancelDetailRequest() {
  detailRequestVersion += 1;
  if (activeDetailRequest) activeDetailRequest.controller.abort();
  activeDetailRequest = null;
  detailDialog.removeAttribute("aria-busy");
  fullBodyToggle.disabled = false;
}

function closeDetail() {
  cancelDetailRequest();
  detailDialog.close();
}

async function copyDetailBody() {
  if (!detailBodyText) return;
  const label = copyBodyButton.querySelector("span");
  try {
    await navigator.clipboard.writeText(detailBodyText);
    label.textContent = "已复制";
    setStatus("请求内容已复制", "ready");
  } catch (error) {
    label.textContent = "复制失败";
    setStatus(safeMessage(error, "无法复制"), "error");
  }
  window.setTimeout(() => {
    label.textContent = "复制 JSON";
  }, 1600);
}

function resetFilters() {
  form.reset();
  setRange("today");
  updateActiveFilterSummary();
  load(true);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  updateActiveFilterSummary();
  load(true);
});
form.addEventListener("input", () => {
  updateActiveFilterSummary();
  updateRangeMetric();
});
function clearActiveRange() {
  activeRange = null;
  rangeButtons.forEach((button) => button.classList.remove("is-active"));
}

startInput.addEventListener("change", clearActiveRange);
endInput.addEventListener("change", clearActiveRange);
rangeButtons.forEach((button) => {
  button.addEventListener("click", () => setRange(button.dataset.range, true));
});
refreshButton.addEventListener("click", () => load(true));
resetButton.addEventListener("click", resetFilters);
emptyResetButton.addEventListener("click", resetFilters);
moreButton.addEventListener("click", () => load(false));
closeDetailButton.addEventListener("click", closeDetail);
copyBodyButton.addEventListener("click", copyDetailBody);
fullBodyToggle.addEventListener("change", () => {
  if (!currentDetail) return;
  loadDetail(
    currentDetail.month,
    currentDetail.id,
    fullBodyToggle.checked ? "full" : "compact",
  );
});
detailDialog.addEventListener("click", (event) => {
  if (event.target === detailDialog) closeDetail();
});
detailDialog.addEventListener("close", cancelDetailRequest);
auditPreferenceToggle.addEventListener("change", async () => {
  const enabled = auditPreferenceToggle.checked;
  auditPreferenceToggle.disabled = true;
  setStatus(enabled ? "正在开启审计" : "正在关闭审计", "loading");
  try {
    const response = await fetch(`${auditBase}/api/preference`, {
      method: "PUT",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "审计设置更新失败");
    renderAuditPreference(payload.enabled);
    setStatus(payload.enabled ? "审计已开启" : "审计已关闭", "ready");
  } catch (error) {
    renderAuditPreference(!enabled);
    setStatus(safeMessage(error, "审计设置更新失败"), "error");
  } finally {
    auditPreferenceToggle.disabled = false;
  }
});

async function initialisePage() {
  setStatus("正在同步时区", "loading");
  try {
    const response = await fetch(`${auditBase}/api/context`, {
      credentials: "same-origin",
      cache: "no-store",
    });
    const payload = await response.json();
    if (!response.ok || !payload.timezone || !payload.viewer?.username) {
      throw new Error(payload.detail || "时区同步失败");
    }
    configureTimeFormatters(payload.timezone);
    serviceTimezone = payload.timezone;
    const serverNowMs = Date.parse(payload.now);
    if (Number.isFinite(serverNowMs)) {
      serverClockOffsetMs = serverNowMs - Date.now();
    }
    timezoneLabel.textContent = serviceTimezone;
    viewerLabel.textContent = payload.viewer.username;
    scopeLabel.textContent = payload.viewer.can_view_all ? "全部记录" : "仅个人记录";
    auditPreferenceControl.hidden = payload.viewer.can_view_all;
    renderAuditPreference(
      Boolean(payload.viewer.audit_enabled),
      !payload.viewer.can_view_all,
    );
    usernameFilterField.hidden = !payload.viewer.can_view_all;
    if (!payload.viewer.can_view_all) {
      usernameFilterField.querySelector("input").value = "";
    }
  } catch (error) {
    timezoneLabel.textContent = `${serviceTimezone} · 回退`;
    viewerLabel.textContent = "身份同步失败";
    scopeLabel.textContent = "权限范围未知";
    setStatus(safeMessage(error, "时区同步失败"), "error");
  }

  initialiseDates();
  updateActiveFilterSummary();
  updateMetrics();
  await load(true);
}

initialisePage();
