// Pagina MITM: trafico HTTPS interceptado y descifrado por mitmproxy.

const mtWindow   = document.getElementById("mtWindow");
const mtMethod   = document.getElementById("mtMethod");
const mtOnlySec  = document.getElementById("mtOnlySec");
const mtRefresh  = document.getElementById("mtRefresh");
const mtBody     = document.getElementById("mtBody");

const mtTotal      = document.getElementById("mtTotal");
const mtTotalSub   = document.getElementById("mtTotalSub");
const mtCreds      = document.getElementById("mtCreds");
const mtJwt        = document.getElementById("mtJwt");
const mtTopHost    = document.getElementById("mtTopHost");
const mtTopHostCnt = document.getElementById("mtTopHostCount");

function fmtNum(n) { return Number(n || 0).toLocaleString(); }
function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  if (n < 1024) return n + " B";
  if (n < 1024*1024) return (n/1024).toFixed(1) + " KB";
  return (n/1024/1024).toFixed(2) + " MB";
}
function fmtTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleTimeString();
}
function escHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function topOf(obj) {
  const entries = Object.entries(obj || {});
  if (!entries.length) return ["-", 0];
  entries.sort((a, b) => b[1] - a[1]);
  return entries[0];
}
function statusClass(s) {
  if (!s) return "";
  if (s < 300) return "ok";
  if (s < 400) return "info";
  if (s < 500) return "warn";
  return "err";
}

async function loadStats() {
  const params = new URLSearchParams({ window: mtWindow.value });
  try {
    const r = await fetch("/api/mitm/stats?" + params);
    const d = await r.json();
    mtTotal.textContent     = fmtNum(d.total);
    mtTotalSub.textContent  = "ventana: " + d.window;
    mtCreds.textContent     = fmtNum(d.with_credentials);
    mtJwt.textContent       = fmtNum(d.with_jwt);
    const [host, cnt] = topOf(d.by_host);
    mtTopHost.textContent     = host;
    mtTopHostCnt.textContent  = fmtNum(cnt) + " peticiones";
  } catch (e) {
    mtTotalSub.textContent = "error: " + e.message;
  }
}

async function loadList() {
  const params = new URLSearchParams({ window: mtWindow.value, size: 200 });
  if (mtMethod.value) params.set("method", mtMethod.value);
  if (mtOnlySec.checked) params.set("only_security", "1");

  try {
    const r = await fetch("/api/mitm/sessions?" + params);
    const d = await r.json();
    if (!d.items || !d.items.length) {
      mtBody.innerHTML = `<tr><td colspan="9" class="empty">
        Sin intercepciones en ${mtWindow.value}. ${d.note || ""}
      </td></tr>`;
      return;
    }
    mtBody.innerHTML = d.items.map(it => {
      const flags = [];
      if (it.has_credentials) flags.push('<span class="tag tag-danger">creds</span>');
      if (it.has_jwt)         flags.push('<span class="tag tag-warn">JWT</span>');
      return `
        <tr class="clickable" onclick="showDetail('${it.id}')">
          <td class="muted">${fmtTime(it.ts)}</td>
          <td><code>${escHtml(it.client_ip)}</code></td>
          <td><span class="m m-${(it.method||'').toLowerCase()}">${escHtml(it.method)}</span></td>
          <td>${escHtml(it.server_host)}</td>
          <td><code>${escHtml(it.path)}</code></td>
          <td class="${statusClass(it.status)}">${escHtml(it.status)}</td>
          <td class="muted">${escHtml(it.resp_ctype || "-")}</td>
          <td class="muted">${fmtBytes(it.resp_size)}</td>
          <td>${flags.join(" ") || ""}</td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    mtBody.innerHTML = `<tr><td colspan="9" class="empty">Error: ${escHtml(e.message)}</td></tr>`;
  }
}

async function showDetail(id) {
  const dlg  = document.getElementById("mtDetail");
  const body = document.getElementById("mtDetailBody");
  const title= document.getElementById("mtDetailTitle");
  body.innerHTML = "<p>Cargando...</p>";
  dlg.showModal();

  try {
    const r = await fetch("/api/mitm/sessions/" + encodeURIComponent(id));
    const d = await r.json();
    if (d.error) {
      body.innerHTML = `<p class="empty">Error: ${escHtml(d.error)}</p>`;
      return;
    }
    const http_ = d.http || {};
    const sec   = d.security || {};
    title.textContent = `${http_.method || ""} ${http_.url || ""}`;

    let secBlock = "";
    if (sec.credentials || sec.jwt_token) {
      secBlock = `<section class="detail-block detail-sec">
        <h3>Hallazgos de seguridad</h3>
        ${sec.credentials ? `<div><strong>Credenciales en claro:</strong>
          <pre>${escHtml(JSON.stringify(sec.credentials, null, 2))}</pre></div>` : ""}
        ${sec.jwt_token ? `<div><strong>JWT capturado:</strong>
          <pre>${escHtml(sec.jwt_token)}</pre>
          ${sec.jwt_payload ? `<div><strong>Payload (decodificado):</strong>
            <pre>${escHtml(JSON.stringify(sec.jwt_payload, null, 2))}</pre></div>` : ""}
          </div>` : ""}
      </section>`;
    }

    body.innerHTML = `
      <section class="detail-block">
        <h3>Resumen</h3>
        <table class="kv">
          <tr><td>Hora</td><td>${escHtml(d["@timestamp"])}</td></tr>
          <tr><td>Cliente</td><td>${escHtml(d.client?.ip)}:${escHtml(d.client?.port)}</td></tr>
          <tr><td>Servidor</td><td>${escHtml(d.server?.hostname)} (${escHtml(d.server?.ip)}:${escHtml(d.server?.port)})</td></tr>
          <tr><td>TLS</td><td>${escHtml(d.tls?.version || "-")}</td></tr>
          <tr><td>Duracion</td><td>${escHtml(d.duration_ms)} ms</td></tr>
          <tr><td>Status</td><td>${escHtml(http_.response_status)} ${escHtml(http_.response_status_text || "")}</td></tr>
        </table>
      </section>

      ${secBlock}

      <section class="detail-block">
        <h3>Request</h3>
        <pre>${escHtml(http_.method)} ${escHtml(http_.path)} ${escHtml(http_.version || "")}</pre>
        <h4>Headers</h4>
        <pre>${escHtml(JSON.stringify(http_.request_headers, null, 2))}</pre>
        ${http_.request_body ? `<h4>Body (${fmtBytes(http_.request_body_size)})</h4>
          <pre>${escHtml(http_.request_body)}</pre>` : ""}
      </section>

      <section class="detail-block">
        <h3>Response</h3>
        <h4>Headers</h4>
        <pre>${escHtml(JSON.stringify(http_.response_headers, null, 2))}</pre>
        ${http_.response_body ? `<h4>Body (${fmtBytes(http_.response_body_size)})</h4>
          <pre>${escHtml(http_.response_body)}</pre>` : ""}
      </section>
    `;
  } catch (e) {
    body.innerHTML = `<p class="empty">Error: ${escHtml(e.message)}</p>`;
  }
}
window.showDetail = showDetail;

function refreshAll() { loadStats(); loadList(); }

mtWindow.addEventListener("change", refreshAll);
mtMethod.addEventListener("change", refreshAll);
mtOnlySec.addEventListener("change", refreshAll);
mtRefresh.addEventListener("click", refreshAll);

refreshAll();
setInterval(refreshAll, 5000);
