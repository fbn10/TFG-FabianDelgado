// Pagina /inteligencia - IPs maliciosas de AbuseIPDB con confidence score.

const tiTotal           = document.getElementById("tiTotal");
const tiTotalSub        = document.getElementById("tiTotalSub");
const tiAvgScore        = document.getElementById("tiAvgScore");
const tiHighScore       = document.getElementById("tiHighScore");
const tiTopCountry      = document.getElementById("tiTopCountry");
const tiTopCountryCount = document.getElementById("tiTopCountryCount");

const tiBody         = document.getElementById("tiBody");
const tiResultsCount = document.getElementById("tiResultsCount");
const tiSearch       = document.getElementById("tiSearch");
const tiFilterMinScore = document.getElementById("tiFilterMinScore");
const tiFilterCountry  = document.getElementById("tiFilterCountry");
const tiPrev         = document.getElementById("tiPrev");
const tiNext         = document.getElementById("tiNext");
const tiPageInfo     = document.getElementById("tiPageInfo");

const tiCheckIp      = document.getElementById("tiCheckIp");
const tiCheckBtn     = document.getElementById("tiCheckBtn");
const tiCheckLiveBtn = document.getElementById("tiCheckLiveBtn");
const tiCheckResult  = document.getElementById("tiCheckResult");

const PAGE_SIZE = 50;
let page = 0;

function fmt(n) { return Number(n || 0).toLocaleString(); }
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
  try {
    const r = await fetch("/api/threat_intel/stats");
    const d = await r.json();
    tiTotal.textContent       = fmt(d.total);
    tiTotalSub.textContent    = "fuente: " + (d.sources ? Object.keys(d.sources).join(", ") : "abuseipdb");
    tiAvgScore.textContent    = (d.avg_score != null ? d.avg_score.toFixed(1) + "%" : "--");
    tiHighScore.textContent   = fmt(d.high_score);
    const [country, count] = Object.entries(d.by_country || {}).sort((a,b)=>b[1]-a[1])[0] || ["--",0];
    tiTopCountry.textContent      = country || "--";
    tiTopCountryCount.textContent = fmt(count) + " IPs";

    const sel = tiFilterCountry;
    const cur = sel.value;
    sel.innerHTML = '<option value="">Todos los paises</option>';
    Object.entries(d.by_country || {}).sort((a,b)=>b[1]-a[1]).forEach(([c, n]) => {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = `${c} (${n})`;
      sel.appendChild(opt);
    });
    sel.value = cur;
  } catch (e) {
    tiTotalSub.textContent = "error: " + e.message;
  }
}

async function loadList() {
  const params = new URLSearchParams({
    size: PAGE_SIZE,
    from: page * PAGE_SIZE,
    min_score: tiFilterMinScore.value,
  });
  if (tiSearch.value)        params.set("search", tiSearch.value);
  if (tiFilterCountry.value) params.set("country", tiFilterCountry.value);

  try {
    const r = await fetch("/api/threat_intel?" + params);
    const d = await r.json();

    tiResultsCount.textContent = `${fmt(d.total)} IPs - pagina ${page+1}`;
    tiPageInfo.textContent     = `pagina ${page+1} de ${Math.max(1, Math.ceil(d.total/PAGE_SIZE))}`;

    if (!d.items || !d.items.length) {
      tiBody.innerHTML = `<tr><td colspan="7" class="empty">Sin resultados.</td></tr>`;
      return;
    }

    tiBody.innerHTML = d.items.map((it, idx) => `
      <tr>
        <td class="muted">${page*PAGE_SIZE + idx + 1}</td>
        <td><code>${escHtml(it.ip)}</code></td>
        <td>${scoreBar(it.abuse_confidence)}</td>
        <td>${escHtml(it.country_code || "--")}</td>
        <td class="muted">${fmtDate(it.last_reported_at)}</td>
        <td><span class="tag">${escHtml(it.source)}</span></td>
        <td class="muted">${escHtml(it.category || "--")}</td>
      </tr>
    `).join("");
  } catch (e) {
    tiBody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${escHtml(e.message)}</td></tr>`;
  }
}

async function checkIp() {
  const ip = (tiCheckIp.value || "").trim();
  if (!ip) {
    tiCheckResult.style.display = "none";
    return;
  }
  try {
    const r = await fetch("/api/threat_intel/check?ip=" + encodeURIComponent(ip));
    const d = await r.json();
    tiCheckResult.style.display = "block";
    if (d.found) {
      tiCheckResult.className = "alert alert-error";
      tiCheckResult.innerHTML = `
        <strong>IP MALICIOSA</strong>: <code>${escHtml(d.ip)}</code>
        - Confidence ${d.abuse_confidence}% (${d.country_code || "?"})
        - Fuente: ${d.source}. Ultimo reporte: ${fmtDate(d.last_reported_at)}`;
    } else {
      tiCheckResult.className = "alert alert-ok";
      tiCheckResult.innerHTML = `<strong>IP limpia</strong>: <code>${escHtml(d.ip)}</code> no aparece en orion-threat-intel.`;
    }
  } catch (e) {
    tiCheckResult.style.display = "block";
    tiCheckResult.className = "alert alert-error";
    tiCheckResult.textContent = "Error: " + e.message;
  }
}

function refreshAll() {
  page = 0;
  loadStats();
  loadList();
}

tiSearch.addEventListener("input",  () => { page=0; loadList(); });
tiFilterMinScore.addEventListener("change", refreshAll);
tiFilterCountry.addEventListener("change",  () => { page=0; loadList(); });
tiPrev.addEventListener("click", () => { if (page > 0) { page--; loadList(); } });
tiNext.addEventListener("click", () => { page++; loadList(); });
tiCheckBtn.addEventListener("click", checkIp);
tiCheckIp.addEventListener("keydown", e => { if (e.key === "Enter") checkIp(); });

async function checkIpLive() {
  const ip = (tiCheckIp.value || "").trim();
  if (!ip) {
    tiCheckResult.style.display = "none";
    return;
  }
  tiCheckResult.style.display = "block";
  tiCheckResult.className = "alert";
  tiCheckResult.textContent = "Consultando AbuseIPDB en vivo (gasta 1 cuota)...";

  try {
    const r = await fetch("/api/threat_intel/check_live?ip=" + encodeURIComponent(ip));
    const d = await r.json();
    if (d.error) {
      tiCheckResult.className = "alert alert-error";
      tiCheckResult.innerHTML = `<strong>Error:</strong> ${escHtml(d.error)}`;
      return;
    }
    const score = d.abuse_confidence;
    if (score === 0) {
      tiCheckResult.className = "alert alert-ok";
      tiCheckResult.innerHTML = `
        <strong>IP limpia segun AbuseIPDB live</strong>: <code>${escHtml(d.ip)}</code>
        - 0% confidence (${escHtml(d.total_reports)} reportes en 90 dias)
        - Pais: ${escHtml(d.country_code || "?")} - ISP: ${escHtml(d.isp || "?")}`;
    } else {
      tiCheckResult.className = "alert alert-error";
      tiCheckResult.innerHTML = `
        <strong>${score}% confidence (live)</strong>: <code>${escHtml(d.ip)}</code>
        - Pais: ${escHtml(d.country_code || "?")} - ISP: ${escHtml(d.isp || "?")}
        - Reportes: ${escHtml(d.total_reports)} - Ultimo: ${fmtDate(d.last_reported_at)}
        ${d.is_tor ? " - <strong>NODO TOR</strong>" : ""}
        ${d.indexed ? " - <em>cacheado en orion-threat-intel</em>" : " - <em>no cacheado</em>"}`;
      // Recargar la lista para que aparezca la IP nueva si tiene score >= filtro
      setTimeout(refreshAll, 800);
    }
  } catch (e) {
    tiCheckResult.className = "alert alert-error";
    tiCheckResult.textContent = "Error: " + e.message;
  }
}

tiCheckLiveBtn.addEventListener("click", checkIpLive);

refreshAll();
