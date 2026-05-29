// Pagina de reglas: tabs por iface + tab de historial.
// Modal compartido para crear y editar.
// Todas las llamadas son contra /api/rules y /api/rules/history.

// DOM refs
const tabs        = document.querySelectorAll("#rulesTabs .dash-tab");
const rulesView   = document.getElementById("rulesView");
const historyView = document.getElementById("historyView");
const rulesBody   = document.getElementById("rulesBody");
const historyBody = document.getElementById("historyBody");
const rulesCount  = document.getElementById("rulesCount");
const modal       = document.getElementById("ruleModal");
const modalTitle  = document.getElementById("modalTitle");
const form        = document.getElementById("ruleForm");
const formError   = document.getElementById("formError");

// Estado en memoria
// Iface activa actualmente (o "__history__" si estamos en el historial)
let currentIface = "enp6s0f0";

// Lista de reglas que devolvio /api/rules en la ultima carga.
// La filtramos por iface en cliente para no pegarle al backend en cada tab.
let allRules = [];

// Helpers
function fmtDate(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", "").replace(/:\d{2}\.\d+$/, "");
}

function tagAction(action) {
  const cls = "tag tag-" + action;
  return `<span class="${cls}">${action.toUpperCase()}</span>`;
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Resumen "humano" del origen / destino de una regla
function fmtEndpoint(ip, port) {
  const i = ip || "*";
  const p = port ? ":" + port : "";
  return escapeHtml(i + p);
}

function fmtLimits(r) {
  const parts = [];
  if (r.limit_pps) parts.push(r.limit_pps + " pps");
  if (r.limit_bps) parts.push(r.limit_bps + " bps");
  return parts.length ? parts.join(" / ") : "—";
}

// Render reglas
function renderRulesForIface(iface) {
  const filtered = allRules
    .filter(r => r.iface === iface)
    .sort((a, b) => (a.priority || 100) - (b.priority || 100));

  rulesCount.textContent = `${filtered.length} regla${filtered.length === 1 ? "" : "s"} activa${filtered.length === 1 ? "" : "s"} en ${iface}`;

  if (!filtered.length) {
    rulesBody.innerHTML = `<tr><td colspan="8" class="empty">Sin reglas activas en ${iface}. Pulsa "+ Nueva regla" para crear una.</td></tr>`;
    return;
  }

  rulesBody.innerHTML = filtered.map(r => `
    <tr>
      <td>${r.priority || 100}</td>
      <td>
        <strong>${escapeHtml(r.name || "(sin nombre)")}</strong>
        ${r.comment ? `<div class="muted" style="font-size: 11px;">${escapeHtml(r.comment)}</div>` : ""}
      </td>
      <td><code>${fmtEndpoint(r.source_ip, r.source_port)}</code></td>
      <td><code>${fmtEndpoint(r.dest_ip, r.dest_port)}</code></td>
      <td><span class="tag">${escapeHtml((r.protocol || "any").toUpperCase())}</span></td>
      <td>${fmtLimits(r)}</td>
      <td>${tagAction(r.action || "drop")}</td>
      <td>
        <button class="btn btn-ghost" data-action="edit"   data-id="${escapeHtml(r.id)}">Editar</button>
        <button class="btn btn-danger" data-action="delete" data-id="${escapeHtml(r.id)}">Borrar</button>
      </td>
    </tr>
  `).join("");
}

// Render historial
function renderHistory(events) {
  if (!events.length) {
    historyBody.innerHTML = '<tr><td colspan="5" class="empty">Sin eventos.</td></tr>';
    return;
  }

  const opTag = op => {
    const colors = { created: "tag-allow", updated: "tag", disabled: "tag-drop", enabled: "tag-allow" };
    return `<span class="tag ${colors[op] || ""}">${op}</span>`;
  };

  historyBody.innerHTML = events.map(ev => {
    const target = ev.new_state || ev.old_state || {};
    const summary = target.name
      ? `${escapeHtml(target.name)} (${escapeHtml(target.iface || "?")})`
      : escapeHtml(ev.rule_id || "");
    const details = [];
    if (target.action)    details.push("action: " + escapeHtml(target.action));
    if (target.protocol)  details.push("proto: " + escapeHtml(target.protocol));
    if (target.source_ip) details.push("src: " + escapeHtml(target.source_ip));
    if (target.dest_ip)   details.push("dst: " + escapeHtml(target.dest_ip));

    return `
      <tr>
        <td class="muted">${fmtDate(ev.timestamp)}</td>
        <td>${opTag(ev.operation)}</td>
        <td><strong>${summary}</strong>
            <div class="muted" style="font-size: 11px;">${escapeHtml(ev.rule_id || "")}</div></td>
        <td>${escapeHtml(ev.user || "—")}</td>
        <td class="muted" style="font-size: 12px;">${details.join(" · ")}</td>
      </tr>
    `;
  }).join("");
}

// Carga datos
async function loadRules() {
  try {
    const r = await fetch("/api/rules");
    const d = await r.json();
    allRules = d.rules || [];
    renderRulesForIface(currentIface);
  } catch (e) {
    rulesBody.innerHTML = `<tr><td colspan="8" class="empty">Error: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadHistory() {
  historyBody.innerHTML = '<tr><td colspan="5" class="empty">Cargando historial...</td></tr>';
  try {
    const r = await fetch("/api/rules/history?size=200");
    const d = await r.json();
    renderHistory(d.events || []);
  } catch (e) {
    historyBody.innerHTML = `<tr><td colspan="5" class="empty">Error: ${escapeHtml(e.message)}</td></tr>`;
  }
}

// Tabs
function activateTab(iface) {
  currentIface = iface;
  tabs.forEach(t => t.classList.toggle("active", t.dataset.iface === iface));

  if (iface === "__history__") {
    rulesView.style.display = "none";
    historyView.style.display = "block";
    loadHistory();
  } else {
    rulesView.style.display = "block";
    historyView.style.display = "none";
    renderRulesForIface(iface);
  }
}

tabs.forEach(t => {
  t.addEventListener("click", () => activateTab(t.dataset.iface));
});

// Modal
function openModalCreate() {
  modalTitle.textContent = "Nueva regla en " + currentIface;
  form.reset();
  form.rule_id.value = "";
  form.iface.value = currentIface;       // pre-selecciona la iface del tab activo
  form.priority.value = "100";
  form.action.value = "drop";
  form.protocol.value = "any";
  formError.style.display = "none";
  modal.classList.add("show");
}

function openModalEdit(rule) {
  modalTitle.textContent = "Editar regla " + (rule.name || rule.id);
  form.reset();
  form.rule_id.value     = rule.id || "";
  form.name.value        = rule.name || "";
  form.iface.value       = rule.iface || "enp6s0f0";
  form.source_ip.value   = rule.source_ip || "";
  form.source_port.value = rule.source_port || "";
  form.dest_ip.value     = rule.dest_ip || "";
  form.dest_port.value   = rule.dest_port || "";
  form.protocol.value    = rule.protocol || "any";
  form.limit_pps.value   = rule.limit_pps || "";
  form.limit_bps.value   = rule.limit_bps || "";
  form.action.value      = rule.action || "drop";
  form.priority.value    = rule.priority || 100;
  form.comment.value     = rule.comment || "";
  formError.style.display = "none";
  modal.classList.add("show");
}

function closeModal() {
  modal.classList.remove("show");
}

document.getElementById("btnNewRule").addEventListener("click", openModalCreate);
document.getElementById("btnCancel").addEventListener("click", closeModal);
document.getElementById("modalClose").addEventListener("click", closeModal);
modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });

// Si el usuario escribe un puerto y el protocolo sigue en 'Cualquiera',
// lo pasamos a TCP a la vista para que vea que se va a filtrar TCP.
["source_port", "dest_port"].forEach((n) => {
  form[n].addEventListener("input", () => {
    if (form[n].value.trim() && form.protocol.value === "any") {
      form.protocol.value = "tcp";
    }
  });
});

// Submit del modal (crear o editar)
function buildPayload() {
  // Solo enviamos los campos que tienen valor. El backend trata los ausentes
  // como wildcards. Asi una regla "solo IP" no manda puerto vacio que confunda.
  const data = {};
  const text = (n) => form[n].value.trim();
  const opt  = (n, t = "string") => {
    const v = text(n);
    if (!v) return;
    data[n] = (t === "int") ? parseInt(v, 10) : v;
  };

  data.iface  = text("iface");
  data.action = text("action");
  data.protocol = text("protocol") || "any";
  opt("name");
  opt("source_ip");
  opt("dest_ip");
  opt("source_port", "int");
  opt("dest_port",   "int");
  opt("limit_pps",   "int");
  opt("limit_bps",   "int");
  opt("priority",    "int");
  opt("comment");

  // Un puerto solo existe en L4. Si hay puerto y el protocolo esta en
  // 'any', asumimos TCP (SSH/HTTP/HTTPS...). UDP se elige a mano.
  if ((data.source_port !== undefined || data.dest_port !== undefined)
      && data.protocol === "any") {
    data.protocol = "tcp";
    form.protocol.value = "tcp";   // feedback visible en el formulario
  }
  return data;
}

function clientValidate(payload) {
  // El backend ya valida, pero damos feedback inmediato
  const hasCriterion =
    !!payload.source_ip || !!payload.dest_ip ||
    (payload.protocol && payload.protocol !== "any") ||
    (payload.source_port !== undefined) || (payload.dest_port !== undefined) ||
    (payload.limit_pps !== undefined)   || (payload.limit_bps !== undefined);
  if (!hasCriterion) {
    return "La regla tiene que tener al menos un criterio (IP, puerto, protocolo o rate-limit).";
  }
  if ((payload.source_port !== undefined || payload.dest_port !== undefined)
      && payload.protocol === "icmp") {
    return "ICMP no tiene puertos. Usa TCP o UDP.";
  }
  return null;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  formError.style.display = "none";

  const ruleId  = form.rule_id.value;
  const payload = buildPayload();

  const err = clientValidate(payload);
  if (err) { formError.textContent = err; formError.style.display = "block"; return; }

  const url    = ruleId ? `/api/rules/${ruleId}` : "/api/rules";
  const method = ruleId ? "PUT" : "POST";

  try {
    const r = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await r.json();
    if (!r.ok) {
      formError.textContent = body.error || "No se pudo guardar";
      formError.style.display = "block";
      return;
    }
    closeModal();
    await loadRules();
  } catch (ex) {
    formError.textContent = "Error de red: " + ex.message;
    formError.style.display = "block";
  }
});

// Acciones por fila (editar / borrar)
rulesBody.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const id     = btn.dataset.id;
  const action = btn.dataset.action;

  if (action === "edit") {
    const rule = allRules.find(r => r.id === id);
    if (!rule) return;
    openModalEdit(rule);
  } else if (action === "delete") {
    if (!confirm(`Desactivar la regla ${id}?`)) return;
    try {
      const r = await fetch("/api/rules/" + id, { method: "DELETE" });
      if (!r.ok) { alert("No se pudo borrar"); return; }
      await loadRules();
    } catch (ex) {
      alert("Error de red: " + ex.message);
    }
  }
});

// Refrescar historial manualmente
document.getElementById("btnRefreshHistory").addEventListener("click", loadHistory);

// Init + polling
loadRules();
// Refresco cada 10s para ver cambios desde otros canales (ej. otra terminal con curl)
setInterval(() => {
  if (currentIface === "__history__") loadHistory();
  else loadRules();
}, 10000);
