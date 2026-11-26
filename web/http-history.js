"use strict";

const byId = (id) => document.getElementById(id);
const fileInput = byId("har-file");
const search = byId("har-search");
const method = byId("har-method");
const status = byId("har-status");
const inspector = byId("har-inspector");
const maxFileSize = 20 * 1024 * 1024;
const previewLimit = 32000;
let entries = [];
let importGeneration = 0;
let selectedEntry = null;
const network = globalThis.chrome?.devtools?.network;
const recordButton = byId("har-record");
const liveLimit = 300;
let recording = false;
let renderTimer = null;

function isRequest(entry) {
  return typeof entry?.request?.url === "string" &&
    typeof entry.request.method === "string" && Number.isInteger(entry.response?.status);
}

function parseHistory(text) {
  const data = JSON.parse(text.replace(/^\uFEFF/, ""));
  if (!Array.isArray(data?.log?.entries)) {
    throw new Error("Choose a HAR file exported from your browser’s Network panel.");
  }
  return data.log.entries.filter(isRequest);
}

function preview(text, empty = "Unavailable in this recording.") {
  if (typeof text !== "string") return empty;
  if (!text.length) return "Empty";
  return text.length > previewLimit ? text.slice(0, previewLimit) + "\n… preview truncated" : text;
}

function formatHeaders(headers) {
  if (!Array.isArray(headers)) return undefined;
  return headers.filter((header) => typeof header?.name === "string" && typeof header.value === "string")
    .map(({ name, value }) => `${name}: ${value}`).join("\n");
}

function elapsed(value) {
  return Number.isFinite(value) && value >= 0 ? `${value.toFixed(1)} ms` : "—";
}

function inspect(entry) {
  selectedEntry = entry;
  const { request, response, timings } = entry;
  inspector.hidden = false;
  byId("har-summary").textContent = `${request.method} · ${response.status || "No response"} · ${elapsed(entry.time)} · ${request.url}`;
  byId("har-request-headers").textContent = preview(formatHeaders(request.headers));
  byId("har-request-body").textContent = preview(request.postData?.text);
  byId("har-response-headers").textContent = preview(formatHeaders(response.headers));
  const content = response.content;
  byId("har-response-body").textContent = content?.encoding === "base64" && typeof content.text === "string"
    ? "Base64-encoded content\n" + preview(content.text)
    : preview(content?.text);
  if (typeof entry.getContent === "function" && typeof content?.text !== "string") {
    byId("har-response-body").textContent = "Reading recorded response…";
    entry.getContent((body, encoding) => {
      if (selectedEntry !== entry) return;
      const text = typeof body === "string" && body.length ? preview(body) : "Response body unavailable in DevTools, or empty.";
      byId("har-response-body").textContent = encoding === "base64" ? "Base64-encoded content\n" + text : text;
    });
  }
  const phases = ["blocked", "dns", "connect", "ssl", "send", "wait", "receive"];
  byId("har-timings").textContent = phases.map((phase) => `${phase}: ${elapsed(timings?.[phase])}`).join("\n");
  inspector.focus();
}

function hideInspector() {
  selectedEntry = null;
  inspector.hidden = true;
  for (const id of ["summary", "request-headers", "request-body", "response-headers", "response-body", "timings"]) {
    byId(`har-${id}`).textContent = "";
  }
}

function renderHistory() {
  const query = search.value.trim().toLowerCase();
  const matches = entries.filter(({ request, response }) =>
    (!method.value || request.method === method.value) &&
    (!status.value || Math.floor(response.status / 100) === Number(status.value)) &&
    request.url.toLowerCase().includes(query));
  const visible = matches.slice(0, 250);
  const fragment = document.createDocumentFragment();
  for (const entry of visible) {
    const row = document.createElement("tr");
    for (const text of [entry.request.method, entry.response.status || "—", elapsed(entry.time)]) {
      row.insertCell().textContent = text;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "har-request";
    button.textContent = entry.request.url;
    button.addEventListener("click", () => inspect(entry));
    row.insertCell().append(button);
    fragment.append(row);
  }
  byId("har-rows").replaceChildren(fragment);
  byId("har-count").textContent = `Showing ${visible.length} of ${matches.length} matching requests`;
  if (!matches.includes(selectedEntry)) hideInspector();
}

function updateMethods() {
  const selectedMethod = method.value;
  const methods = [...new Set(entries.map(({ request }) => request.method))].sort();
  const options = document.createDocumentFragment();
  options.append(new Option("All methods", ""));
  for (const name of methods) options.append(new Option(name, name));
  method.replaceChildren(options);
  method.value = methods.includes(selectedMethod) ? selectedMethod : "";
}

function loadHistory(records) {
  entries = records;
  updateMethods();
  method.value = "";
  search.value = "";
  status.value = "";
  byId("har-clear").disabled = !entries.length;
  renderHistory();
}

fileInput.addEventListener("change", async () => {
  const [file] = fileInput.files;
  if (!file) return;
  stopRecording();
  const generation = ++importGeneration;
  fileInput.value = "";
  try {
    if (file.size > maxFileSize) throw new Error("Choose a HAR file of 20 MB or less.");
    const records = parseHistory(await file.text());
    if (generation !== importGeneration) return;
    loadHistory(records);
    byId("status").textContent = `${file.name} · ${records.length} HTTP requests loaded locally`;
  } catch (error) {
    if (generation !== importGeneration) return;
    const message = error instanceof SyntaxError ? "The selected file is not valid JSON." : error.message;
    byId("status").textContent = message + (entries.length ? " The previous recording is still open." : "");
  }
});
byId("har-clear").addEventListener("click", () => {
  importGeneration++;
  stopRecording();
  loadHistory([]);
  byId("status").textContent = "History cleared.";
});
function recordFinished(entry) {
  if (!recording || !isRequest(entry)) return;
  entries.unshift(entry);
  if (entries.length > liveLimit) entries.pop();
  if (renderTimer !== null) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    updateMethods();
    byId("har-clear").disabled = false;
    renderHistory();
  }, 150);
}

function stopRecording() {
  if (!recording) return;
  recording = false;
  network.onRequestFinished.removeListener(recordFinished);
  recordButton.textContent = "Start recording";
  clearTimeout(renderTimer);
  renderTimer = null;
  updateMethods();
  byId("har-clear").disabled = !entries.length;
  renderHistory();
  byId("status").textContent = `Recording stopped · ${entries.length} requests retained`;
}

if (network?.onRequestFinished) {
  byId("traffic-link").hidden = true;
  recordButton.hidden = false;
  byId("status").textContent = "Start recording, then reload or use the inspected tab.";
  recordButton.addEventListener("click", () => {
    if (recording) {
      stopRecording();
      return;
    }
    importGeneration++;
    loadHistory([]);
    recording = true;
    network.onRequestFinished.addListener(recordFinished);
    recordButton.textContent = "Stop recording";
    byId("status").textContent = "Recording completed requests from the inspected tab · latest 300 retained";
  });
}

for (const input of [search, method, status]) input.addEventListener("input", renderHistory);
renderHistory();
