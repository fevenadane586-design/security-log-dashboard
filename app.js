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
  // The path is everything between the method and "HTTP/x.x", so spaces in the path are kept
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

    // Brute force: 5+ failures inside any 5-minute window
    let bruteFound = false;
    for (let i = 0; i + 4 <
