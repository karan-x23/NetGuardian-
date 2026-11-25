"use strict";

const headers = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
const number = new Intl.NumberFormat();
const get = (id) => document.getElementById(id);
let packets = [];
let source = "";
let summary = {};
let importId = 0;
let duration = 0;
let playhead = null;
let replayTimer = null;
let selectedBucket = null;
let destinationFilter = null;
let bucketWidth = 1000;
let timedCount = 0;
let deviceImportId = 0;
let devices = new Map();
let wifiReading = null;
const liveAvailable = location.protocol === "http:" && location.hostname === "127.0.0.1";
let liveMode = liveAvailable;
let liveGeneration = 0;
const activityHeaders = ["Timestamp", "IP", "Name", "MAC", "Type", "Domain", "Service"];

function packetTime(value) {
  const match = /^(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/.exec(value.trim());
  if (!match) return null;
  const [, hours, minutes, seconds, fraction = ""] = match;
  if (+hours > 23 || +minutes > 59 || +seconds > 59) return null;
  return (+hours * 3600 + +minutes * 60 + +seconds) * 1000 + Number(fraction.padEnd(3, "0"));
}

function setSessionTimes(rows) {
  const day = 86_400_000;
  let previous = null;
  let dayOffset = 0;
  let first = null;
  duration = 0;
  timedCount = 0;
  for (const row of rows) {
    const timestamp = packetTime(row.time);
    row.elapsed = null;
    if (timestamp === null) continue;
    if (previous !== null && previous - timestamp > day / 2) dayOffset += day;
    previous = timestamp;
    const absolute = dayOffset + timestamp;
    first ??= absolute;
    row.elapsed = Math.max(absolute - first, 0);
    duration = Math.max(duration, row.elapsed);
    timedCount++;
  }
  bucketWidth = Math.max(1000, Math.ceil((duration + 1) / 48 / 1000) * 1000);
}

function elapsedLabel(ms) {
  const seconds = Math.floor(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function intervalLabel(index) {
  return `${elapsedLabel(index * bucketWidth)}–${elapsedLabel((index + 1) * bucketWidth)}`;
}

function stopReplay() {
  clearInterval(replayTimer);
  replayTimer = null;
}

function toggleReplay() {
  if (replayTimer !== null) {
    stopReplay();
    render();
    return;
  }
  if (playhead === null || playhead >= duration) playhead = 0;
  selectedBucket = null;
  destinationFilter = null;
  let last = performance.now();
  replayTimer = setInterval(() => {
    const now = performance.now();
    playhead = Math.min(duration, playhead + (now - last) * Number(get("speed").value));
    last = now;
    if (playhead >= duration) stopReplay();
    render();
  }, 200);
  render();
}

function renderTimeline(rows) {
  const chart = get("timeline");
  const count = timedCount ? Math.floor(duration / bucketWidth) + 1 : 0;
  const buckets = Array.from({ length: count }, () => ({ packets: 0, bytes: 0 }));
  for (const row of rows) {
    if (row.elapsed === null) continue;
    const bucket = buckets[Math.floor(row.elapsed / bucketWidth)];
    bucket.packets++;
    bucket.bytes += row.length;
  }
  const peak = Math.max(1, ...buckets.map((bucket) => bucket.packets));
  // Reuse the buttons while replay runs so keyboard focus stays on the selected interval.
  if (chart.childElementCount !== count) {
    chart.replaceChildren(...buckets.map((_, index) => {
      const button = element("button");
      button.type = "button";
      button.addEventListener("click", () => {
        stopReplay();
        selectedBucket = selectedBucket === index ? null : index;
        render();
      });
      return button;
    }));
  }
  buckets.forEach((bucket, index) => {
    const button = chart.children[index];
    const label = `${intervalLabel(index)} · ${number.format(bucket.packets)} packets · ${number.format(bucket.bytes)} B`;
    button.title = label;
    button.setAttribute("aria-label", label);
    button.setAttribute("aria-pressed", String(selectedBucket === index));
    button.style.setProperty("--bar-height", `${bucket.packets / peak * 100}%`);
  });
  get("time-start").textContent = count ? "0:00" : "";
  get("time-end").textContent = count ? elapsedLabel(count * bucketWidth) : "";
  const replayStatus = liveMode ? "Live window" : playhead === null ? "Full session" :
    `${replayTimer !== null ? "Playing" : playhead >= duration ? "Replay complete" : "Paused"} · ${elapsedLabel(playhead)}`;
  const omitted = packets.length - timedCount;
  get("timeline-note").textContent = count ?
    `${replayStatus} · ${bucketWidth / 1000}s intervals · select a bar to inspect it${omitted ? ` · ${number.format(omitted)} rows without usable timestamps` : ""}` :
    "No packet timestamps available.";
  get("replay").textContent = replayTimer !== null ? "Pause" :
    playhead !== null && playhead < duration ? "Resume" : "Replay";
  get("replay").disabled = liveMode || duration === 0;
  get("speed").disabled = liveMode;
  get("show-all").disabled = playhead === null && selectedBucket === null;
}

function readCsvRows(text, expectedHeaders, headerError) {
  // Quoted fields can contain commas, newlines and escaped double quotes.
  const tokens = /("(?:[^"]|"")*"|[^",\r\n]*)(,|\r\n|\n|\r|$)/y;
  const rows = [];
  let row = [];
  let offset = 0;
  text = text.replace(/^\uFEFF/, "");
  while (offset < text.length || (offset > 0 && text[offset - 1] === "," && row.length)) {
    tokens.lastIndex = offset;
    const match = tokens.exec(text);
    if (!match || (match[0] === "" && offset < text.length)) {
      throw new Error("Invalid CSV quoting.");
    }
    const [, field, separator] = match;
    row.push(field.startsWith('"') ? field.slice(1, -1).replaceAll('""', '"') : field);
    offset = tokens.lastIndex;
    if (separator !== ",") {
      if (row.some((value) => value !== "")) rows.push(row);
      row = [];
    }
  }

  const columns = rows.shift();
  if (!columns || columns.length !== expectedHeaders.length ||
      expectedHeaders.some((header, i) => columns[i].trim() !== header)) {
    throw new Error(headerError);
  }
  return rows;
}

function parseCsv(text) {
  return readCsvRows(text, headers, "Choose a packet CSV created by NetGuardian’s Export button.").map((row, i) => {
    const [id, time, source, destination, protocol, rawLength, info] = row;
    const length = Number(rawLength);
    if (row.length !== headers.length || !/^\d+$/.test(rawLength.trim()) ||
        !Number.isSafeInteger(length) || !time.trim() || !protocol.trim()) {
      throw new Error(`Invalid packet data in record ${i + 1}.`);
    }
    return { id, time, source, destination, protocol: protocol.trim().toUpperCase(), length, info };
  });
}

function countBy(rows, key) {
  const counts = new Map();
  for (const row of rows) {
    const value = row[key];
    if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function element(tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function render() {
  const query = get("search").value.trim().toLowerCase();
  const protocol = get("protocol").value;
  const thresholdInput = get("threshold");
  const threshold = thresholdInput.validity.valid && thresholdInput.value ? thresholdInput.valueAsNumber : null;
  const available = packets.filter((packet) =>
    (playhead === null || (packet.elapsed !== null && packet.elapsed <= playhead)) &&
    (!protocol || packet.protocol === protocol) &&
    [packet.source, packet.destination, packet.info].some((value) => value.toLowerCase().includes(query))
  );
  renderTimeline(available.filter((packet) => !destinationFilter || packet.destination === destinationFilter));
  const intervalRows = available.filter((packet) => selectedBucket === null ||
    (packet.elapsed !== null && Math.floor(packet.elapsed / bucketWidth) === selectedBucket));
  const matching = intervalRows.filter((packet) => !destinationFilter || packet.destination === destinationFilter);
  const scopes = [];
  if (selectedBucket !== null) scopes.push(intervalLabel(selectedBucket));
  if (destinationFilter) scopes.push(destinationFilter);
  get("scope").hidden = scopes.length === 0;
  get("scope-text").textContent = scopes.join(" · ");
  const volume = matching.reduce((total, packet) => total + packet.length, 0);
  const destinations = countBy(matching, "destination");
  const protocols = countBy(matching, "protocol");
  const alerts = threshold === null ? [] : destinations.filter(([, count]) => count >= threshold);
  get("packets").textContent = number.format(matching.length);
  get("volume").textContent = number.format(volume) + " B";
  get("destinations").textContent = number.format(destinations.length);

  const bars = protocols.map(([name, count]) => {
    const row = element("li");
    const bar = element("progress");
    bar.max = matching.length;
    bar.value = count;
    bar.setAttribute("aria-label", name + " packet share");
    row.append(element("span", name), bar, element("span", number.format(count)));
    return row;
  });
  get("distribution").replaceChildren(...(bars.length ? bars : [element("li", "No matching packets.")]));
  const alertRows = alerts.slice(0, 10).map(([address, count]) => {
    const row = element("li");
    const button = element("button", `${address} · ${number.format(count)} packets`);
    button.type = "button";
    button.setAttribute("aria-pressed", String(destinationFilter === address));
    button.addEventListener("click", () => {
      stopReplay();
      destinationFilter = destinationFilter === address ? null : address;
      render();
      get(destinationFilter || selectedBucket !== null ? "clear-scope" : "search").focus();
    });
    row.append(button);
    return row;
  });
  const evidence = get("alert-evidence");
  evidence.hidden = !destinationFilter;
  evidence.textContent = destinationFilter ?
    `${destinationFilter} · ${number.format(matching.length)} matching packets · threshold ${threshold ?? "unset"}${protocols.length ? " · " + protocols.map(([name, count]) => name + " " + number.format(count)).join(" / ") : ""}` : "";
  if (alerts.length > 10) alertRows.push(element("li", `Showing 10 of ${number.format(alerts.length)} destinations.`));
  if (!alertRows.length) alertRows.push(element("li", threshold === null ?
    "Enter a whole number of 1 or higher." : "No destinations reached the threshold."));
  get("alerts").replaceChildren(...alertRows);

  const visible = matching.slice(-200).reverse();
  get("row-count").textContent = `Showing ${number.format(visible.length)} of ${number.format(matching.length)} matching packets, newest rows first.`;
  get("rows").replaceChildren(...visible.map((packet) => {
    const row = element("tr");
    for (const key of ["time", "source", "destination", "protocol", "length", "info"]) {
      row.append(element("td", packet[key]));
    }
    return row;
  }));
  summary = { source, filters: { query, protocol, threshold, destination: destinationFilter,
    intervalSeconds: selectedBucket === null ? null : [selectedBucket * bucketWidth / 1000, (selectedBucket + 1) * bucketWidth / 1000],
    replayElapsedSeconds: playhead === null ? null : playhead / 1000 }, packets: matching.length, bytes: volume,
    destinationCount: destinations.length, protocols: Object.fromEntries(protocols),
    alerts: alerts.map(([destination, packets]) => ({ destination, packets })) };
  get("download").disabled = threshold === null;
}

function parseDeviceActivity(text) {
  return readCsvRows(text, activityHeaders, "Expected columns: " + activityHeaders.join(", ")).map((row, i) => {
    const [timestamp, ip, name, mac, type, domain, service] = row.map((value) => value.trim());
    const parts = ip?.split(".") ?? [];
    if (row.length !== activityHeaders.length || parts.length !== 4 ||
        parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) ||
        (mac && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) || (domain && !timestamp)) {
      throw new Error(`Invalid device activity in record ${i + 1}. Use IPv4 addresses and colon-separated MAC addresses.`);
    }
    return { timestamp, ip, name, mac: mac.toLowerCase(), type, domain: domain.toLowerCase().replace(/\.$/, ""), service };
  });
}

function loadDevices(records, label) {
  const picker = get("device");
  const selected = picker.value;
  devices = new Map();
  for (const record of records) {
    const { ip, mac, name, type, timestamp, domain, service } = record;
    const device = devices.get(ip) ?? { ip, mac: "", name: "", type: "", last: "", bytes: 0, activity: new Map() };
    if (device.mac && mac && device.mac !== mac) {
      get("device-status").textContent = `Multiple MAC addresses share ${ip}. Import one inventory snapshot per session.`;
      devices = new Map();
      break;
    }
    device.mac ||= mac ?? "";
    device.name ||= name ?? "";
    device.type ||= type ?? "";
    if (timestamp > device.last) device.last = timestamp;
    if (domain) {
      const key = JSON.stringify([domain, service]);
      const group = device.activity.get(key) ?? { domain, service, count: 0, last: "" };
      group.count++;
      if (timestamp > group.last) group.last = timestamp;
      device.activity.set(key, group);
    }
    devices.set(ip, device);
  }
  if (devices.size || !records.length) get("device-status").textContent = label;
  for (const packet of packets) {
    for (const ip of new Set([packet.source, packet.destination])) {
      const device = devices.get(ip);
      if (device) device.bytes += packet.length;
    }
  }
  const options = document.createDocumentFragment();
  for (const device of devices.values()) {
    options.append(new Option(device.name ? `${device.name} · ${device.ip}` : device.ip, device.ip));
  }
  picker.replaceChildren(options);
  picker.disabled = !devices.size;
  if (devices.has(selected)) picker.value = selected;
  renderDevice();
}

function renderRadar() {
  const radar = get("radar");
  const selected = get("device").value;
  const visible = [...devices.values()].slice(0, 24);
  if (selected && !visible.some((device) => device.ip === selected)) {
    visible.splice(visible.length - 1, 1, devices.get(selected));
  }
  const previous = new Map(Array.from(radar.children, (button) => [button.dataset.ip, button]));
  const wanted = new Set(visible.map((device) => device.ip));
  for (const [ip, button] of previous) {
    if (!wanted.has(ip)) button.remove();
  }
  visible.forEach((device, index) => {
    let button = previous.get(device.ip);
    if (!button) {
      button = element("button");
      button.type = "button";
      button.dataset.ip = device.ip;
      button.className = "radar-device";
      button.addEventListener("click", () => {
        get("device").value = device.ip;
        renderDevice();
        get("device").focus();
      });
      radar.append(button);
    }
    const ring = index < 6 ? 0 : index < 14 ? 1 : 2;
    const start = [0, 6, 14][ring];
    const slots = [6, 8, 10][ring];
    const angle = ((index - start) / slots + ring / 20) * 2 * Math.PI - Math.PI / 2;
    const radius = [20, 32, 43][ring];
    button.style.left = `${50 + radius * Math.cos(angle)}%`;
    button.style.top = `${50 + radius * Math.sin(angle)}%`;
    button.title = device.name ? `${device.name} · ${device.ip}` : device.ip;
    button.setAttribute("aria-label", button.title);
    button.setAttribute("aria-pressed", String(selected === device.ip));
  });
  get("radar-count").textContent = devices.size
    ? `${number.format(devices.size)} observed devices${devices.size > visible.length ? ` · ${visible.length} on radar` : ""}`
    : "No devices observed yet.";
  const signal = wifiReading?.signal;
  const meter = get("wifi-meter");
  meter.hidden = !Number.isFinite(signal);
  if (!meter.hidden) meter.value = signal;
  get("wifi-label").textContent = meter.hidden ? "Wi-Fi signal unavailable" :
    `${wifiReading.adapter} · Wi-Fi signal ${signal}%`;
}

function renderDevice() {
  renderRadar();
  const device = devices.get(get("device").value);
  const facts = get("device-facts");
  const activity = get("device-activity");
  facts.replaceChildren();
  activity.replaceChildren();
  if (!device) return;
  const fields = [
    ["Name", device.name || "Unknown"], ["Type", device.type || "Unknown"],
    ["IP address", device.ip], ["MAC address", device.mac || "Unavailable"],
    ["Last observed", device.last || "Unavailable"], ["Bytes in packet session", number.format(device.bytes)],
  ];
  for (const [name, value] of fields) {
    const fact = element("div");
    fact.append(element("dt", name), element("dd", value));
    facts.append(fact);
  }
  const groups = [...device.activity.values()].sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain));
  for (const group of groups.slice(0, 100)) {
    const row = element("tr");
    for (const value of [group.domain, group.service || "Unknown", number.format(group.count), group.last]) {
      row.append(element("td", value));
    }
    activity.append(row);
  }
  if (!groups.length || groups.length > 100) {
    const row = element("tr");
    const cell = element("td", groups.length ? `Showing 100 of ${number.format(groups.length)} entries.` : "No domain records for this device.");
    cell.colSpan = 4;
    row.append(cell);
    activity.append(row);
  }
}

get("device").addEventListener("change", renderDevice);
get("device-file").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  const id = ++deviceImportId;
  event.target.value = "";
  try {
    if (file.size > 10 * 1024 * 1024) throw new Error("Choose a CSV smaller than 10 MB.");
    const records = parseDeviceActivity(await file.text());
    if (id === deviceImportId) loadDevices(records, `${file.name} · imported device activity`);
  } catch (error) {
    if (id === deviceImportId) get("device-status").textContent = error.message;
  }
});

function load(rows, label) {
  deviceImportId++;
  stopReplay();
  playhead = null;
  selectedBucket = null;
  destinationFilter = null;
  setSessionTimes(rows);
  packets = rows;
  source = label;
  wifiReading = null;
  loadDevices([], "Import an authorized inventory and activity CSV from the same session.");
  get("search").value = "";
  get("protocol").replaceChildren(new Option("All protocols", ""),
    ...countBy(rows, "protocol").map(([name]) => new Option(name, name)));
  get("status").textContent = `${label} · ${number.format(rows.length)} packets`;
  render();
}

get("file").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  const id = ++importId;
  event.target.value = "";
  try {
    if (file.size > 10 * 1024 * 1024) throw new Error("Choose a CSV smaller than 10 MB.");
    const rows = parseCsv(await file.text());
    if (id === importId) {
      liveMode = false;
      liveGeneration++;
      get("return-live").hidden = !liveAvailable;
      get("device-file").disabled = false;
      load(rows, file.name);
    }
  } catch (error) {
    if (id === importId) get("status").textContent = `${error.message} Still showing ${source}.`;
  }
});

async function pollLive() {
  const generation = liveGeneration;
  try {
    const response = await fetch("live.json", { cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error("Live feed unavailable");
    const data = await response.json();
    if (!liveMode || generation !== liveGeneration) return;
    const previousFirst = packets[0]?.id;
    const previousBucketWidth = bucketWidth;
    packets = data.packets.map(([id, time, source, destination, protocol, length, info]) =>
      ({ id, time, source, destination, protocol, length, info }));
    setSessionTimes(packets);
    if (previousFirst !== packets[0]?.id || previousBucketWidth !== bucketWidth) selectedBucket = null;
    const picker = get("protocol");
    const selected = picker.value;
    const names = countBy(packets, "protocol").map(([name]) => name).sort();
    if (Array.from(picker.options).slice(1).map((option) => option.value).join("|") !== names.join("|")) {
      picker.replaceChildren(new Option("All protocols", ""), ...names.map((name) => new Option(name, name)));
      picker.value = names.includes(selected) ? selected : "";
    }
    const activity = [...data.devices];
    const known = new Set(data.devices.map((device) => device.ip));
    const prefix = "Standard query ";
    for (const packet of packets) {
      if (known.has(packet.source) && packet.protocol === "DNS" &&
          packet.info.startsWith(prefix) && !packet.info.startsWith(prefix + "response ")) {
        const domain = packet.info.slice(prefix.length).trim().toLowerCase();
        if (domain) activity.push({ ip: packet.source, domain, service: "", timestamp: packet.time });
      }
    }
    wifiReading = data.wifi;
    loadDevices(activity, activity.length ? "Live inventory and observed DNS requests" : "No devices observed yet.");
    source = "Live capture";
    get("status").textContent = `${data.running ? "Capture running" : "Capture stopped · Start capture in the desktop app"} · ${number.format(packets.length)} recent packets · ${number.format(data.total)} captured`;
    render();
  } catch (error) {
    if (liveMode && generation === liveGeneration) {
      wifiReading = null;
      renderRadar();
      get("status").textContent = "Live feed disconnected. Displayed data may be stale. Reconnecting…";
    }
  } finally {
    if (liveMode && generation === liveGeneration) setTimeout(pollLive, 1000);
  }
}

function startLive() {
  importId++;
  liveGeneration++;
  liveMode = true;
  load([], "Connecting to live capture…");
  get("return-live").hidden = true;
  get("device-file").disabled = true;
  pollLive();
}

get("return-live").addEventListener("click", startLive);
get("replay").addEventListener("click", toggleReplay);
get("show-all").addEventListener("click", () => {
  stopReplay();
  playhead = null;
  selectedBucket = null;
  render();
});
get("clear-scope").addEventListener("click", () => {
  selectedBucket = null;
  destinationFilter = null;
  render();
  get("search").focus();
});
for (const id of ["search", "protocol", "threshold"]) get(id).addEventListener("input", render);
get("print").addEventListener("click", () => window.print());
get("download").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(summary, null, 2)], { type: "application/json" }));
  const link = element("a");
  link.href = url;
  link.download = "netguardian-summary.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
if (liveAvailable) startLive();
else load([], "Open Live web dashboard in the desktop app, or import a recorded packet CSV.");
