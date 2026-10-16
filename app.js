const $ = function (id) { return document.getElementById(id); };
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
let currentAlerts = [];

const HINTS = {
  auth: "Expected format: Oct 14 09:02:03 srv01 sshd[2301]: Failed password for root from 198.51.100.23 port 33001 ssh2",
  web: 'Expected format: 198.51.100.23 - - [14/Oct/2026:09:10:01 +0000] "GET /path HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
};

function updateHint() { $("format-hint").textContent = HINTS[$("log-type").value]; }
$("log-type").addEventListener("change", updateHint);
updateHint();

// ---------- Parsing ----------
function parseAuth(text) {
  const events = [];
  const lines = text.split("\n").filter(function (l) { return l.trim(); });
  const re = /^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+sshd\[\d+\]:\s+(Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)/;
  lines.forEach(function (line) {
    const m = line.match(re);
    if (!m) return;
    const time = new Date(2026, MONTHS[m[1]], parseInt(m[2], 10), +m[3], +m[4], +m[5]);
    events.push({ time: time, status: m[6], user: m[7], ip: m[8], raw: line });
  });
  return { lines: lines.length, events: events };
}

function parseWeb(text) {
  const events = [];
  const lines = text.split("\n").filter(function (l) { return l.trim(); });
  const re = /^([\d.]+)\s+\S+\s+\S+\s+\[(\d+)\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})[^\]]*\]\s+"(\S+)\s+(.*?)\s+HTTP\/[\d.]+"\s+(\d{3})\s+\S+\s+"[^"]*"\s+"([^"]*)"/;
  lines.forEach(function (line) {
    const m = line.match(re);
    if (!m) return;
    const time = new Date(+m[4], MONTHS[m[3]], +m[2], +m[5], +m[6], +m[7]);
    events.push({ time: time, ip: m[1], method: m[8], path: m[9], status: +m[10], agent: m[11], raw: line });
  });
  return { lines: lines.length, events: events };
}

// ---------- Detection: auth logs ----------
function detectAuth(events) {
  const alerts = [];
  const byIp = {};
  events.forEach(function (e) {
    (byIp[e.ip] = byIp[e.ip] || []).push(e);
  });

  Object.keys(byIp).forEach(function (ip) {
    const list = byIp[ip].slice().sort(function (a, b) { return a.time - b.time; });
    const fails = list.filter(function (e) { return e.status === "Failed"; });

    let bruteFound = false;
    for (let i = 0; i + 4 < fails.length && !bruteFound; i++) {
      if (fails[i + 4].time - fails[i].time <= 5 * 60 * 1000) {
        alerts.push({
          severity: "High", rule: "Brute force login", mitre: "T1110.001", ip: ip,
          evidence: "5+ failed logins within 5 minutes (" + fails.length + " failures total)"
        });
        bruteFound = true;
      }
    }

    const users = {};
    fails.forEach(function (e) { users[e.user] = true; });
    const userCount = Object.keys(users).length;
    if (userCount >= 4) {
      alerts.push({
        severity: "High", rule: "Password spraying", mitre: "T1110.003", ip: ip,
        evidence: "Failed against " + userCount + " different usernames: " + Object.keys(users).join(", ")
      });
    }

    let streak = 0;
    let flagged = false;
    list.forEach(function (e) {
      if (e.status === "Failed") {
        streak++;
      } else {
        if (streak >= 3 && !flagged) {
          alerts.push({
            severity: "High", rule: "Suspicious successful login", mitre: "T1078", ip: ip,
            evidence: "Login as '" + e.user + "' succeeded after " + streak + " consecutive failures"
          });
          flagged = true;
        }
        streak = 0;
      }
    });

    if (fails.length >= 2 && !alerts.some(function (a) { return a.ip === ip; })) {
      alerts.push({
        severity: "Low", rule: "Repeated failed logins", mitre: "T1110", ip: ip,
        evidence: fails.length + " failed logins, below the brute force threshold"
      });
    }
  });
  return alerts;
}

// ---------- PART 2 STARTS BELOW THIS LINE ----------



// ---------- Detection: web logs ----------
const WEB_RULES = [
  { name: "SQL injection", severity: "High", mitre: "T1190",
    re: /(union(\s|%20|\+)+select|'\s*or\s*'?1'?\s*=\s*'?1|or\s+1\s*=\s*1|drop\s+table|--\s|%27)/i },
  { name: "Cross-site scripting", severity: "High", mitre: "T1190",
    re: /(<script|%3cscript|onerror\s*=|onload\s*=|javascript:)/i },
  { name: "Path traversal", severity: "High", mitre: "T1083",
    re: /(\.\.\/|\.\.%2f|%2e%2e|etc\/passwd|win\.ini)/i }
];
const SCANNER_AGENTS = /(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|acunetix|nessus)/i;

function detectWeb(events) {
  const alerts = [];
  const seen = {};
  const notFound = {};
  const scannerIps = {};

  events.forEach(function (e) {
    let decoded = e.path;
    try { decoded = decodeURIComponent(e.path); } catch (err) { /* keep raw */ }

    WEB_RULES.forEach(function (rule) {
      if (rule.re.test(e.path) || rule.re.test(decoded)) {
        const key = rule.name + "|" + e.ip;
        if (!seen[key]) {
          seen[key] = true;
          alerts.push({
            severity: rule.severity, rule: rule.name, mitre: rule.mitre, ip: e.ip,
            evidence: e.method + " " + e.path.slice(0, 90) + " (status " + e.status + ")"
          });
        }
      }
    });

    if (e.status === 404) notFound[e.ip] = (notFound[e.ip] || 0) + 1;
    if (SCANNER_AGENTS.test(e.agent)) scannerIps[e.ip] = e.agent;
  });

  Object.keys(scannerIps).forEach(function (ip) {
    alerts.push({
      severity: "Medium", rule: "Scanner activity", mitre: "T1595", ip: ip,
      evidence: "Known scanner user agent: " + scannerIps[ip] + " (" + (notFound[ip] || 0) + " not-found responses)"
    });
  });
  Object.keys(notFound).forEach(function (ip) {
    if (notFound[ip] >= 5 && !scannerIps[ip]) {
      alerts.push({
        severity: "Medium", rule: "Scanner activity", mitre: "T1595", ip: ip,
        evidence: notFound[ip] + " not-found responses suggest directory probing"
      });
    }
  });
  return alerts;
}

// ---------- Charts (plain SVG) ----------
function barChart(container, labels, values, color) {
  container.innerHTML = "";
  if (!values.length) { container.textContent = "No data."; return; }
  const W = 460, H = 220, padL = 34, padB = 46, padT = 10;
  const max = Math.max.apply(null, values.concat([1]));
  const bw = (W - padL - 10) / values.length;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);

  function add(tag, attrs, text) {
    const el = document.createElementNS(ns, tag);
    Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    if (text !== undefined) el.textContent = text;
    svg.appendChild(el);
  }

  add("line", { x1: padL, y1: padT, x2: padL, y2: H - padB, stroke: "#999" });
  add("line", { x1: padL, y1: H - padB, x2: W - 6, y2: H - padB, stroke: "#999" });
  add("text", { x: padL - 6, y: padT + 8, "text-anchor": "end", "font-size": 10, fill: "#555" }, String(max));
  add("text", { x: padL - 6, y: H - padB, "text-anchor": "end", "font-size": 10, fill: "#555" }, "0");

  values.forEach(function (v, i) {
    const h = (v / max) * (H - padB - padT);
    const x = padL + i * bw + 4;
    const y = H - padB - h;
    add("rect", { x: x, y: y, width: Math.max(bw - 8, 4), height: h, fill: color });
    add("text", { x: x + (bw - 8) / 2, y: y - 3, "text-anchor": "middle", "font-size": 10, fill: "#222" }, String(v));
    const lx = x + (bw - 8) / 2;
    add("text", { x: lx, y: H - padB + 14, "text-anchor": "middle", "font-size": 9, fill: "#555" }, labels[i]);
  });
  container.appendChild(svg);
}

function renderCharts(events, type) {
  const hours = {};
  events.forEach(function (e) {
    if (type === "auth" && e.status !== "Failed") return;
    const h = e.time.getHours();
    hours[h] = (hours[h] || 0) + 1;
  });
  const hourKeys = Object.keys(hours).map(Number).sort(function (a, b) { return a - b; });
  $("chart1-title").textContent = type === "auth" ? "Failed logins per hour" : "Requests per hour";
  barChart($("chart-hours"), hourKeys.map(function (h) { return h + ":00"; }),
    hourKeys.map(function (h) { return hours[h]; }), "#1565c0");

  const ips = {};
  events.forEach(function (e) {
    if (type === "auth" && e.status !== "Failed") return;
    ips[e.ip] = (ips[e.ip] || 0) + 1;
  });
  const top = Object.keys(ips).sort(function (a, b) { return ips[b] - ips[a]; }).slice(0, 6);
  $("chart2-title").textContent = type === "auth" ? "Top IPs by failed logins" : "Top IPs by requests";
  barChart($("chart-ips"), top, top.map(function (ip) { return ips[ip]; }), "#c62828");
}

// ---------- Rendering ----------
function renderAlerts(alerts) {
  const tbody = document.querySelector("#alert-table tbody");
  tbody.innerHTML = "";
  const order = { High: 0, Medium: 1, Low: 2 };
  alerts.sort(function (a, b) { return order[a.severity] - order[b.severity]; });

  alerts.forEach(function (a) {
    const tr = document.createElement("tr");
    const cells = [null, a.rule, a.mitre, a.ip, a.evidence];
    cells.forEach(function (text, i) {
      const td = document.createElement("td");
      if (i === 0) {
        const span = document.createElement("span");
        span.className = "sev " + a.severity;
        span.textContent = a.severity;
        td.appendChild(span);
      } else {
        td.textContent = text;
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  $("no-alerts").classList.toggle("hidden", alerts.length > 0);
  $("alert-table").classList.toggle("hidden", alerts.length === 0);
}

function analyze() {
  const type = $("log-type").value;
  const text = $("log-input").value;
  if (!text.trim()) { alert("Load sample data, upload a file, or paste some log lines first."); return; }

  const parsed = type === "auth" ? parseAuth(text) : parseWeb(text);
  const alerts = type === "auth" ? detectAuth(parsed.events) : detectWeb(parsed.events);

  const ipSet = {};
  parsed.events.forEach(function (e) { ipSet[e.ip] = true; });

  $("s-lines").textContent = parsed.lines;
  $("s-parsed").textContent = parsed.events.length;
  $("s-ips").textContent = Object.keys(ipSet).length;
  $("s-alerts").textContent = alerts.length;

  renderCharts(parsed.events, type);
  renderAlerts(alerts);
  currentAlerts = alerts;
  $("btn-csv").disabled = alerts.length === 0;
  $("dashboard").classList.remove("hidden");
}

// ---------- CSV export ----------
function csvCell(value) {
  let s = String(value);
  if (/^[=+\-@]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

function exportCsv() {
  const rows = [["Severity", "Rule", "MITRE", "Source IP", "Evidence"]];
  currentAlerts.forEach(function (a) { rows.push([a.severity, a.rule, a.mitre, a.ip, a.evidence]); });
  const csv = rows.map(function (r) { return r.map(csvCell).join(","); }).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "alerts.csv";
  link.click();
  URL.revokeObjectURL(link.href);
}

// ---------- Events ----------
$("btn-sample").addEventListener("click", function () {
  $("log-input").value = $("log-type").value === "auth" ? SAMPLE_AUTH : SAMPLE_WEB;
});
$("btn-analyze").addEventListener("click", analyze);
$("btn-csv").addEventListener("click", exportCsv);
$("log-file").addEventListener("change", function () {
  const file = $("log-file").files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function () { $("log-input").value = reader.result; };
  reader.readAsText(file);
});

