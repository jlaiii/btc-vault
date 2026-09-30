/* Progressive enhancement only — every feature works without JS. */
(function () {
  "use strict";

  var toastTimer = null;
  function toast(msg) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2100);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); resolve(); }
      catch (e) { reject(e); }
      finally { document.body.removeChild(ta); }
    });
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (btn) {
      ev.preventDefault();
      var value = btn.getAttribute("data-copy");
      copyText(value).then(function () {
        toast("Copied");
        var label = btn.getAttribute("data-copied-label");
        if (label) {
          var original = btn.textContent;
          btn.textContent = label;
          setTimeout(function () { btn.textContent = original; }, 1500);
        }
      }).catch(function () { toast("Copy failed — select it manually"); });
      return;
    }
    var act = ev.target.closest("[data-confirm]");
    if (act && !window.confirm(act.getAttribute("data-confirm"))) {
      ev.preventDefault();
      ev.stopPropagation();
      return;
    }
    // single-submit: stop double-taps from sending twice. With several submit
    // buttons in one form (e.g. the account-security card) disable the button
    // that was actually pressed, not the first one in the form.
    var btn = ev.target.closest('button[type="submit"],input[type="submit"]');
    var form = btn ? btn.form : null;
    if (!form) form = ev.target.closest("form[data-once]");
    if (form && form.hasAttribute("data-once") && form.checkValidity &&
        form.checkValidity()) {
      var submitBtn = btn || form.querySelector('[type="submit"]');
      if (submitBtn && !submitBtn.disabled) {
        setTimeout(function () { submitBtn.disabled = true; }, 0);
      }
    }
  });

  // ---- live conversion: BTC <-> USD while typing ----
  function wireConverter() {
    var input = document.getElementById("amount");
    var out = document.getElementById("amountUsd");
    var price = parseFloat(document.body.getAttribute("data-price") || "0");
    if (!input || !out || !price) return;

    function update() {
      var raw = (input.value || "").trim().replace(/,/g, "");
      if (!/^\d*(\.\d{0,8})?$/.test(raw) || raw === "" || raw === ".") {
        out.textContent = "";
        return;
      }
      var btc = parseFloat(raw);
      if (isNaN(btc)) { out.textContent = ""; return; }
      out.textContent = "≈ $" + (btc * price).toLocaleString(undefined,
        { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }
    input.addEventListener("input", update);

    var max = document.querySelector("[data-max]");
    if (max) {
      max.addEventListener("click", function (ev) {
        ev.preventDefault();
        input.value = max.getAttribute("data-max");
        update();
        input.focus();
      });
    }
    update();
  }

  // ---- fee tier selection styling ----
  function wireFees() {
    var fees = document.querySelectorAll(".fee input[type=radio]");
    if (!fees.length) return;
    function paint() {
      document.querySelectorAll(".fee").forEach(function (row) {
        var radio = row.querySelector("input[type=radio]");
        row.classList.toggle("sel", !!(radio && radio.checked));
      });
    }
    fees.forEach(function (r) { r.addEventListener("change", paint); });
    paint();
  }

  // ---- password strength meter ----
  function wireStrength() {
    var pw = document.getElementById("password");
    var bar = document.getElementById("pwBar");
    if (!pw || !bar) return;
    var fill = bar.querySelector("span");
    var label = document.getElementById("pwLabel");
    pw.addEventListener("input", function () {
      var v = pw.value, score = 0;
      if (v.length >= 10) score++;
      if (v.length >= 14) score++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
      if (/\d/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v)) score++;
      var pct = Math.min(100, score * 20);
      fill.style.width = pct + "%";
      fill.style.background = score <= 2 ? "var(--err)"
        : score === 3 ? "var(--warn)" : "var(--ok)";
      if (label) {
        label.textContent = !v ? "" : score <= 2 ? "Weak"
          : score === 3 ? "Okay" : score === 4 ? "Good" : "Strong";
      }
    });
  }

  // ---- auto-refresh the wallet page so incoming deposits appear ----
  function wireAutoRefresh() {
    var el = document.querySelector("[data-refresh]");
    if (!el) return;
    var secs = parseInt(el.getAttribute("data-refresh"), 10) || 60;
    var last = Date.now();
    setInterval(function () {
      if (document.hidden) return;
      if (Date.now() - last < secs * 1000) return;
      // only reload when nothing is being typed into
      var active = document.activeElement;
      if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA")) return;
      last = Date.now();
      window.location.reload();
    }, 5000);
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireConverter();
    wireFees();
    wireStrength();
    wireAutoRefresh();
  });
})();
