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
