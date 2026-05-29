// Modal de confirmacion global de ORION.
//
// Uso desde JS:
//   const ok = await openModal({
//     variant:      "danger" | "success" | "" (default azul),
//     icon:         "!" | "+" | "?" | ...,
//     title:        "Texto del titulo",
//     body:         "HTML del cuerpo (admite <code>, <strong>, <br>, ...)",
//     confirmLabel: "Si, hacerlo",
//     confirmClass: "orion-btn-danger" | "orion-btn-success" | "orion-btn-primary",
//     hideCancel:   true   // para modal informativo de un solo boton
//   });
//   if (ok) { ... }
//
// Atajos:
//   Esc          -> cancelar
//   Click fuera  -> cancelar

(function () {
  let _resolver = null;

  function ensureDom() {
    // Si ya existe un modal en el DOM (por cache o versiones anteriores),
    // lo borramos para garantizar que el nuestro tiene los listeners
    // correctos via event delegation.
    const old = document.getElementById("orionModalBackdrop");
    if (old) old.remove();

    const html = `
      <div class="orion-modal-backdrop" id="orionModalBackdrop" role="dialog" aria-modal="true">
        <div class="orion-modal" id="orionModal">
          <div class="orion-modal-icon" id="orionModalIcon">?</div>
          <h3 id="orionModalTitle">Confirmar accion</h3>
          <p id="orionModalBody">...</p>
          <div class="orion-modal-actions">
            <button class="orion-btn orion-btn-secondary" id="orionModalCancel" type="button">Cancelar</button>
            <button class="orion-btn orion-btn-primary"   id="orionModalConfirm" type="button">Confirmar</button>
          </div>
        </div>
      </div>`;
    document.body.insertAdjacentHTML("beforeend", html);
  }

  // Event delegation: una sola vez en document. Robusto frente a DOM
  // recreado, html cacheado del navegador o listeners perdidos.
  // closest() asegura que funciona aunque el click caiga en un nodo
  // hijo del boton (ej. icon span).
  document.addEventListener("click", function (e) {
    if (!e.target || !e.target.closest) return;
    if (e.target.closest("#orionModalConfirm")) {
      e.preventDefault();
      window.closeModal(true);
      return;
    }
    if (e.target.closest("#orionModalCancel")) {
      e.preventDefault();
      window.closeModal(false);
      return;
    }
    if (e.target.id === "orionModalBackdrop") {
      // click justo en el fondo (no dentro del card)
      window.closeModal(false);
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    const bd = document.getElementById("orionModalBackdrop");
    if (bd && bd.classList.contains("open")) {
      e.preventDefault();
      window.closeModal(false);
    }
  });

  window.openModal = function (opts) {
    ensureDom();
    const bd     = document.getElementById("orionModalBackdrop");
    const card   = document.getElementById("orionModal");
    const icon   = document.getElementById("orionModalIcon");
    const title  = document.getElementById("orionModalTitle");
    const body   = document.getElementById("orionModalBody");
    const ok     = document.getElementById("orionModalConfirm");
    const cancel = document.getElementById("orionModalCancel");

    card.className    = "orion-modal " + (opts.variant || "");
    icon.textContent  = opts.icon || "?";
    title.textContent = opts.title || "Confirmar";
    body.innerHTML    = opts.body  || "";
    ok.textContent    = opts.confirmLabel || "Confirmar";
    ok.className      = "orion-btn " + (opts.confirmClass || "orion-btn-primary");
    cancel.style.display = opts.hideCancel ? "none" : "";

    // Si ya habia una promesa pendiente (modal anidado, etc.), resolvemos a
    // false para no dejar callers colgados.
    if (_resolver) { _resolver(false); _resolver = null; }

    bd.classList.add("open");
    return new Promise(function (resolve) { _resolver = resolve; });
  };

  window.closeModal = function (result) {
    const bd = document.getElementById("orionModalBackdrop");
    if (bd) bd.classList.remove("open");
    if (_resolver) { _resolver(result); _resolver = null; }
  };
})();
