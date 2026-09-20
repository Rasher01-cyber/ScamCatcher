(function () {
  "use strict";

  function toastInvalid(form, message) {
    let alert = form.querySelector(".js-inline-alert");
    if (!alert) {
      alert = document.createElement("div");
      alert.className = "alert alert-warning js-inline-alert py-2";
      form.prepend(alert);
    }
    alert.textContent = message;
  }

  document.querySelectorAll("form.check-form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      const kind = form.getAttribute("data-validate");

      if (kind === "smart") {
        const input = form.querySelector('[name="smart_input"]');
        const msg = form.querySelector('[name="message"]');
        const file = form.querySelector('[name="qr_image"]');
        const hasInput = input && input.value.trim();
        const hasMsg = msg && msg.value.trim();
        const hasFile = file && file.files && file.files.length;
        if (!hasInput && !hasMsg && !hasFile) {
          event.preventDefault();
          toastInvalid(form, "Enter a UPI ID, mobile number, QR link, message, or upload a QR image.");
          return;
        }
      }

      if (kind === "report") {
        const upi = form.querySelector('[name="upi_id"]');
        if (upi && !/@/.test(upi.value)) {
          event.preventDefault();
          toastInvalid(form, "Enter a UPI ID like name@oksbi.");
          upi.focus();
          return;
        }
      }

      const btn = form.querySelector('button[type="submit"]');
      if (btn && !btn.disabled) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Working…';
      }
    });
  });

  const ring = document.querySelector(".score-ring[data-score]");
  if (ring) {
    const target = Number(ring.getAttribute("data-score") || 0);
    ring.style.setProperty("--score", "0");
    requestAnimationFrame(function () {
      ring.style.transition = "background 0.9s ease";
      ring.style.setProperty("--score", String(target));
    });
  }

  // Toggle name fields when existence = invalid
  const inv = document.getElementById("ex-inv");
  const reg = document.getElementById("ex-reg");
  const nameFields = document.getElementById("name-fields");
  function syncNameFields() {
    if (!nameFields) return;
    const hide = inv && inv.checked;
    nameFields.style.display = hide ? "none" : "";
    const nameInput = document.getElementById("payee-name");
    if (hide && nameInput) nameInput.value = "";
  }
  inv && inv.addEventListener("change", syncNameFields);
  reg && reg.addEventListener("change", syncNameFields);
})();
