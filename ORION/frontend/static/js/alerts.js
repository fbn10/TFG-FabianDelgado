// Pagina /alertas - cruce on-the-fly Packetbeat <-> AbuseIPDB.

const alWindow       = document.getElementById("alWindow");
const alMinScore     = document.getElementById("alMinScore");
const alRefresh      = document.getElementById("alRefresh");
const alLastUpdate   = document.getElementById("alLastUpdate");

const alTotal        = document.getElementById("alTotal");
const alTotalSub     = document.getElementById("alTotalSub");
const alCritical     = document.getElementById("alCritical");
const alAvgScore     = document.getElementById("alAvgScore");
const alConnections  = document.getElementById("alConnections");
const alTopCountry   = document.getElementById("alTopCountry");

const alBody         = document.getElementById("alBody");

function fmt(n)   { return Number(n || 0).toLocaleString(); }
function escHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function fmtDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}
function scoreClass(s) {
  s = Number(s) || 0;
  if (s >= 90) return "score-critical";
  if (s >= 75) return "score-high";
  if (s >= 50) return "score-medium";
  return "score-low";
}
function scoreBar(score) {
  const s = Number(score) || 0;
  return `
    <div class="score-cell">
      <div class="score-bar"><div class="score-fill ${scoreClass(s)}" style="width:${s}%"></div></div>
      <span class="score-num">${s}%</span>
    </div>`;
}

async function loadStats() {
  const params = new URLSearchParams({
    window:    alWindow.value,
    min_score: alMinScore.value,
  });
  try {
    const r = await fetch("/api/alerts/stats?" + params);
    const d = await r.json();
    alTotal.textContent     = fmt(d.total);
    alTotalSub.textContent  = `ventana: ${d.window}, score >= ${d.min_score}%`;
    alCritical.textContent  = fmt(d.critical);
    alAvgScore.textContent  = (d.avg_score != null ? d.avg_score.toFixed(1) + "%" : "--");
    alConnections.textContent = fmt(d.total_connections);
    alTopCountry.textContent = `top pais: ${d.top_country} (${fmt(d.top_country_count)})`;
  } catch (e) {
    alTotalSub.textContent = "error: " + e.message;
  }
}

async function loadList() {
  const params = new URLSearchParams({
    window:    alWindow.value,
    min_score: alMinScore.value,
    size:      200,
  });
  try {
    const r = await fetch("/api/alerts?" + params);
    const d = await r.json();

    if (!d.items || !d.items.length) {
      alBody.innerHTML = `<tr><td colspan="7" class="empty">
        Sin alertas en ${alWindow.value} con score &ge; ${alMinScore.value}%.
        ${d.note || "Todo OK."}
      </td></tr>`;
      return;
    }

    alBody.innerHTML = d.items.map((it, idx) => `
      <tr>
        <td class="muted">${idx+1}</td>
        <td><code>${escHtml(it.ip)}</code></td>
        <td>${scoreBar(it.abuse_confidence)}</td>
        <td>${escHtml(it.country_code || "--")}</td>
        <td><strong>${fmt(it.connections)}</strong></td>
        <td class="muted">${fmtDate(it.last_reported_at)}</td>
        <td><span class="tag">${escHtml(it.source)}</span></td>
      </tr>
    `).join("");
  } catch (e) {
    alBody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${escHtml(e.message)}</td></tr>`;
  }
}

function refreshAll() {
  loadStats();
  loadList();
  alLastUpdate.textContent = "Ultima actualizacion: " + new Date().toLocaleTimeString();
}

alWindow.addEventListener("change", refreshAll);
alMinScore.addEventListener("change", refreshAll);
alRefresh.addEventListener("click", refreshAll);

refreshAll();
setInterval(refreshAll, 5000);
