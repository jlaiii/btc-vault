/* BTC Vault demo — client-side only.
   Simulates the wallet and admin panel with fake data. No network calls, no backend,
   no bitcoin. Mirrors the real templates in app/templates/ so the shapes match. */

(function () {
  "use strict";

  var PRICE = 84250;            // fixed demo BTC/USD price
  var FEE_RATES = { fast: 12, normal: 6, economy: 2 };   // sat/vB, fixed for the demo
  var VSIZE = 141;              // vB for 1-in / 2-out, measured from the real signer
  var SERVICE_PCT = 0.5;        // percent
  var SERVICE_MIN = 1000;       // sats

  var VIEWS = ["wallet", "receive", "send", "activity", "security", "account", "admin"];

  var S = {
    view: "wallet",
    price: PRICE,
    address: "tb1qdemoxvault0example0address0notreal00zz",
    balance: 4125000,           // sats the logged-in user holds
    activity: [],
    filter: "all",
    tier: "normal",
    totp: false,
    backupCodes: 10,
    logins: [],
    sendQuote: null,
    users: [],
    adminTab: "overview",
    openUser: 2                  // index into S.users
  };

  /* ---------------------------------------------------------------- helpers */
  function sats(n) { return new Intl.NumberFormat("en-US").format(n); }
  function btc(n) { return (n / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, ""); }
  function usd(n) {
    var v = (n / 1e8) * S.price;
    return "$" + v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function pct(n) { return n.toFixed(2) + "%"; }
  function short(s, head, tail) {
    if (!s) return "";
    head = head || 12; tail = tail || 6;
    return s.length <= head + tail + 3 ? s : s.slice(0, head) + "…" + s.slice(-tail);
  }
  function el(id) { return document.getElementById(id); }
  function h(html) { var d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstChild; }

  function flash(kind, text) {
    var box = el("flash");
    box.innerHTML = "";
    box.appendChild(h('<div class="flash ' + kind + '">' + text + "</div>"));
    window.clearTimeout(flash._t);
    flash._t = window.setTimeout(function () { box.innerHTML = ""; }, 7000);
  }

  function toast(msg) {
    var t = el("toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.add("show");
    window.clearTimeout(toast._t);
    toast._t = window.setTimeout(function () { t.classList.remove("show"); }, 1800);
  }

  /* ---------------------------------------------------------------- fee math */
  function quote(amount) {
    var service = Math.max(SERVICE_MIN, Math.round(amount * SERVICE_PCT / 100));
    var network = FEE_RATES[S.tier] * VSIZE;
    return { amount: amount, service: service, network: network, total: amount + service + network };
  }

  /* ---------------------------------------------------------------- seed data */
  function seed() {
    S.balance = 4125000;
    S.totp = false;
    S.backupCodes = 10;
    S.tier = "normal";
    S.filter = "all";
    S.sendQuote = null;
    S.activity = [
      { kind: "deposit", dir: "in", amount: 1500000, status: "confirmed", conf: 42,
        who: "tb1qyou…4f9c2a", when: "2 hours ago", txid: "8f2c41ab7de90c5f31b6a7d84e0c19f2b3a5d6e7091c4f8a2b6d3e5c7a9f1b4d" },
      { kind: "withdrawal", dir: "out", amount: 250000, status: "confirmed", conf: 8,
        who: "bc1qmerchant…7d1e", when: "yesterday", txid: "1a9f3c5e7b2d4068a1c3e5f7092b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e80" },
      { kind: "withdrawal", dir: "out", amount: 120000, status: "queued", conf: 0,
        who: "bc1qhardware…9b3c", when: "yesterday", txid: null },
      { kind: "deposit", dir: "in", amount: 500000, status: "confirmed", conf: 220,
        who: "tb1qfriend…1a7d3e", when: "3 days ago", txid: "c4e6b8d0f2a4c6e80123456789abcdef0123456789abcdef0123456789abcdef" },
      { kind: "faucet_credit", dir: "in", amount: 25000, status: "confirmed", conf: 512,
        who: "testnet faucet", when: "5 days ago", txid: "9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877665544" }
    ];
    S.logins = [
      { kind: "login_ok", ip: "203.0.113.24", when: "2 hours ago", ok: true },
      { kind: "2fa_setup", ip: "203.0.113.24", when: "6 days ago", ok: true },
      { kind: "login_fail", ip: "198.51.100.7", when: "6 days ago", ok: false }
    ];
    S.users = [
      { name: "operator", role: "admin", status: "active", balance: 0, totp: true,
        require: false, mustchange: false, locked: false, negative: false, last: "2 hours ago" },
      { name: "andres_r", role: "user", status: "active", balance: 5250000, totp: true,
        require: false, mustchange: false, locked: false, negative: false, last: "yesterday" },
      { name: "maria_g", role: "user", status: "active", balance: 4125000, totp: false,
        require: false, mustchange: false, locked: false, negative: false, last: "2 hours ago" },
      { name: "beto_h", role: "user", status: "frozen", balance: 880000, totp: false,
        require: false, mustchange: false, locked: false, negative: true, last: "3 days ago" },
      { name: "carlos_v", role: "user", status: "active", balance: 0, totp: false,
        require: false, mustchange: false, locked: true, negative: false, last: "5 days ago" }
    ];
  }

  /* ---------------------------------------------------------------- views */
  function renderWallet() {
    var held = S.users.reduce(function (a, u) { return a + u.balance; }, 0);
    var fees = 184500;
    var onchain = held + fees;
    el("v-balance").textContent = btc(S.balance);
    el("v-balance-usd").innerHTML = "≈ " + usd(S.balance) +
      ' <span class="dim">at $' + sats(S.price) + "/BTC</span>";

    var rows = el("v-recent");
    rows.innerHTML = "";
    S.activity.slice(0, 4).forEach(function (a) {
      rows.appendChild(itemRow(a));
    });

    el("v-holdings").textContent = sats(onchain) + " sat";
    el("v-owed").textContent = sats(held) + " sat";
    el("v-fees").textContent = sats(fees) + " sat";
    el("v-invariant").innerHTML = (onchain - held === fees)
      ? '<span class="pill ok">identity holds</span> on-chain − owed = fees'
      : '<span class="pill fail">shortfall</span>';
  }

  function itemRow(a) {
    var labels = { deposit: "Deposit", withdrawal: "Withdrawal", faucet_credit: "Testnet faucet" };
    var sub = a.when + " · " + a.status + (a.conf ? " · " + a.conf + " confirmations" : "");
    return h(
      '<div class="item">' +
      '<span class="ico ' + (a.dir === "in" ? "in" : a.dir === "out" ? "out" : "hold") + '">' +
      (a.dir === "in" ? "↓" : "↑") + "</span>" +
      '<div class="grow"><div class="t">' + labels[a.kind] + "</div>" +
      '<div class="s">' + sub + " · " + short(a.txid || a.who, 10, 6) + "</div></div>" +
      '<div class="amt ' + (a.dir === "in" ? "pos" : "neg") + '">' +
      (a.dir === "in" ? "+" : "−") + sats(a.amount) + "</div></div>"
    );
  }

  function renderActivity() {
    var box = el("v-activity");
    box.innerHTML = "";
    var rows = S.activity.filter(function (a) {
      if (S.filter === "all") return true;
      if (S.filter === "in") return a.dir === "in";
      if (S.filter === "out") return a.dir === "out";
      return a.kind === S.filter;
    });
    if (!rows.length) {
      box.appendChild(h('<div class="empty">Nothing here yet.</div>'));
      return;
    }
    rows.forEach(function (a) { box.appendChild(itemRow(a)); });
  }

  function renderSend() {
    var box = el("v-send-review");
    var confirmBtn = el("v-send-confirm");
    var actions = el("v-send-review-actions");
    if (!S.sendQuote) {
      box.innerHTML = ""; box.classList.add("hide");
      confirmBtn.classList.add("hide");
      actions.textContent = "";
      return;
    }
    box.classList.remove("hide");
    confirmBtn.classList.remove("hide");
    var q = quote(S.sendQuote);
    actions.textContent = "Balance after this send: " + sats(S.balance - q.total) +
      " sat (before it is confirmed on-chain).";
    box.innerHTML =
      '<label>You send</label><input type="text" readonly value="' + btc(q.amount) + ' BTC">' +
      '<label>Service fee (' + pct(SERVICE_PCT) + ', min ' + sats(SERVICE_MIN) + ' sat)</label>' +
      '<input type="text" readonly value="' + sats(q.service) + ' sat">' +
      '<label>Network fee (' + FEE_RATES[S.tier] + ' sat/vB × ' + VSIZE + ' vB)</label>' +
      '<input type="text" readonly value="' + sats(q.network) + ' sat">' +
      '<label>Total</label><input type="text" readonly value="' + sats(q.total) + ' sat ≈ ' + usd(q.total) + '">' +
      "";
  }

  function renderSecurity() {
    el("v-2fa-state").innerHTML = S.totp
      ? '<span class="pill ok">Enabled</span>'
      : '<span class="pill fail">Off</span>';
    el("v-2fa-detail").textContent = S.totp
      ? "Backup codes remaining: " + S.backupCodes
      : "Add a second factor so a stolen password is not enough.";
    el("v-2fa-action").textContent = S.totp ? "Turn off 2FA" : "Set up two-factor authentication";
    el("v-2fa-action").className = "btn " + (S.totp ? "danger" : "primary");

    var list = el("v-logins");
    list.innerHTML = "";
    S.logins.forEach(function (e) {
      list.appendChild(h(
        '<div class="item"><span class="ico ' + (e.ok ? "in" : "out") + '">' +
        (e.ok ? "✓" : "!") + '</span><div class="grow"><div class="t">' +
        e.kind.replace(/_/g, " ") + '</div><div class="s">' + e.when + " · " + e.ip +
        "</div></div></div>"
      ));
    });
  }

  function gateOf(u) {
    if (u.require && !u.totp) return "require_2fa";
    if (u.mustchange) return "password";
    if (u.locked) return "locked";
    return null;
  }

  function renderAdminOverview() {
    var held = S.users.reduce(function (a, u) { return a + u.balance; }, 0);
    var fees = 184500;
    var onchain = held + fees;
    var queued = S.activity.filter(function (a) { return a.status === "queued"; });
    var no2fa = S.users.filter(function (u) { return !u.totp; }).length;
    var mustEnrol = S.users.filter(function (u) { return u.require && !u.totp; }).length;
    var mustChange = S.users.filter(function (u) { return u.mustchange; }).length;
    var locked = S.users.filter(function (u) { return u.locked; }).length;

    el("a-onchain").textContent = sats(onchain);
    el("a-owed").textContent = sats(held);
    el("a-fees").textContent = sats(fees);
    el("a-accounts").textContent = S.users.length;
    el("a-gates").textContent = no2fa;
    el("a-gate-sub").innerHTML = "without 2FA of " + S.users.length + " accounts" +
      (mustEnrol ? " · " + mustEnrol + " required to enrol" : "") +
      (mustChange ? " · " + mustChange + " must change password" : "") +
      (locked ? " · " + locked + " locked out" : "");
    el("a-invariant").innerHTML = (onchain - held === fees)
      ? '<span class="pill ok">identity holds</span> on-chain − user balances = operator fees'
      : '<span class="pill fail">FLOAT SHORTFALL</span> the books do not balance';

    var q = el("a-queue");
    q.innerHTML = "";
    if (!queued.length) {
      q.appendChild(h('<div class="empty">Nothing waiting for approval.</div>'));
    } else {
      queued.forEach(function (a) {
        q.appendChild(h(
          '<div class="item"><span class="ico hold">⏸</span><div class="grow">' +
          '<div class="t">' + sats(a.amount) + ' sat to ' + short(a.who, 10, 4) + '</div>' +
          '<div class="s">above the auto-send limit · held from the balance</div></div>' +
          '<button class="btn sm primary" data-approve="1">Approve</button>' +
          '<button class="btn sm ghost" data-reject="1">Reject</button></div>'
        ));
      });
    }
  }

  function userBadges(u) {
    var out = "";
    if (u.role === "admin") out += '<span class="badge admin">admin</span> ';
    if (u.totp) out += '<span class="pill ok">2FA on</span> ';
    else out += '<span class="pill fail">2FA off</span> ';
    if (u.require) out += '<span class="pill info">2FA required</span> ';
    if (u.mustchange) out += '<span class="pill pend">new password required</span> ';
    if (u.locked) out += '<span class="pill fail">locked out</span> ';
    if (u.negative) out += '<span class="pill fail">negative balance</span> ';
    if (u.status === "frozen") out += '<span class="pill pend">frozen</span> ';
    return out;
  }

  function renderAdminUsers() {
    var filter = el("a-filter").value;
    var box = el("a-users");
    box.innerHTML = "";
    var rows = S.users.filter(function (u) {
      if (filter === "all") return true;
      if (filter === "no2fa") return !u.totp;
      if (filter === "require2fa") return u.require;
      if (filter === "pending2fa") return u.require && !u.totp;
      if (filter === "mustchange") return u.mustchange;
      if (filter === "locked") return u.locked;
      return true;
    });
    if (!rows.length) {
      box.appendChild(h('<div class="empty">No accounts match that filter.</div>'));
      return;
    }
    rows.forEach(function (u) {
      var idx = S.users.indexOf(u);
      box.appendChild(h(
        '<div class="item"><div class="grow"><div class="t">' + u.name + " " +
        userBadges(u) + '</div><div class="s">balance ' + btc(u.balance) +
        " BTC · last seen " + u.last + "</div></div>" +
        '<button class="btn sm ghost" data-open-user="' + idx + '">Open</button></div>'
      ));
    });
  }

  function renderAdminUser() {
    var u = S.users[S.openUser];
    if (!u) return;
    el("a-user-name").textContent = u.name;
    el("a-user-badges").innerHTML = userBadges(u);
    el("a-user-balance").textContent = btc(u.balance);
    el("a-user-flags").innerHTML =
      '<span class="k">2FA</span><span class="v">' + (u.totp ? "enabled" : "not enabled") + "</span>" +
      '<span class="k">2FA required</span><span class="v">' + (u.require ? "yes" : "no") + "</span>" +
      '<span class="k">Password change</span><span class="v">' + (u.mustchange ? "required" : "not required") + "</span>" +
      '<span class="k">Status</span><span class="v">' + u.status + "</span>";

    var adminTarget = u.role === "admin";
    el("a-user-controls").innerHTML = adminTarget
      ? '<div class="notice info" style="margin-top:0"><strong>Administrator account — exempt from these gates.</strong> ' +
        "Requiring 2FA or a password change means the account cannot reach this panel until it complies, " +
        "so forcing either on an operator locks them out of the switch that turns it off. Manage your own 2FA " +
        "in Account → Security.</div>"
      : adminControls(u);

    var gate = gateOf(u);
    var next = gate === "require_2fa"
      ? '<span class="mono">302 → /security/2fa</span> — every page except the setup page and sign-out is blocked'
      : gate === "password"
        ? '<span class="mono">302 → /account/password/required</span> — they must set a new password'
        : gate === "locked"
          ? '<span class="mono">429</span> at sign-in — locked out after too many failed attempts'
          : '<span class="mono">200</span> — the wallet loads normally';
    el("a-user-gate").innerHTML = next;
  }

  function adminControls(u) {
    var html = '<div class="btn-row" style="margin-top:.2rem">';
    html += u.require
      ? '<button class="btn" data-act="require_off">Stop requiring 2FA</button>'
      : '<button class="btn primary" data-act="require_on">Require 2FA</button>';
    if (u.totp) html += '<button class="btn warn" data-act="clear_2fa">Remove 2FA (lost device)</button>';
    html += "</div>";
    html += '<div class="btn-row">';
    html += u.mustchange
      ? '<button class="btn" data-act="pw_off">Stop requiring a new password</button>'
      : '<button class="btn primary" data-act="pw_on">Require a new password</button>';
    html += "</div>";
    html += '<div class="btn-row">';
    html += '<button class="btn" data-act="unlock">' +
      (u.locked ? "Unlock account" : "Clear failed-attempt counter") + "</button>";
    if (u.negative) html += '<button class="btn warn" data-act="clear_negative">Clear negative-balance flag</button>';
    html += "</div>";
    html += '<div class="sim-note">In the real panel these actions sit behind one inline password ' +
      "confirmation on the same card — nothing is bounced to another page, so the button you press " +
      "is the one that runs.</div>";
    return html;
  }

  function renderAll() {
    renderWallet();
    renderActivity();
    renderSend();
    renderSecurity();
    renderAdminOverview();
    renderAdminUsers();
    renderAdminUser();
  }

  /* ---------------------------------------------------------------- actions */
  function applyAdminAction(act) {
    var u = S.users[S.openUser];
    if (!u) return;
    if (act === "require_on") {
      u.require = true;
      flash("success", "<strong>" + u.name + " must now enrol 2FA.</strong> Their next request — " +
        "including any open session — lands on the setup page.");
    } else if (act === "require_off") {
      u.require = false;
      flash("success", u.name + " is no longer required to use 2FA.");
    } else if (act === "clear_2fa") {
      u.totp = false;
      flash("warning", "2FA cleared for " + u.name + (u.require
        ? " — still required, so they must enrol again at the next sign-in."
        : " — they can sign in with just their password until they enrol again."));
    } else if (act === "pw_on") {
      u.mustchange = true;
      flash("success", "<strong>" + u.name + " must set a new password.</strong> Their next " +
        "request lands on the change-password page; the balance is untouched.");
    } else if (act === "pw_off") {
      u.mustchange = false;
      flash("success", "Password-change requirement lifted for " + u.name + ".");
    } else if (act === "unlock") {
      var was = u.locked;
      u.locked = false;
      flash("success", was
        ? u.name + " can sign in again — failed attempts and the lockout are cleared."
        : "Counters cleared for " + u.name + " (no active lockout).");
    } else if (act === "clear_negative") {
      if (u.balance < 0) {
        flash("error", u.name + " is still at a negative balance — fix the balance first. " +
          "The flag only exists to match reality.");
      } else {
        u.negative = false;
        flash("success", "Negative-balance flag cleared for " + u.name + ".");
      }
    }
    renderAll();
  }

  function confirmSend() {
    if (!S.sendQuote) return;
    var q = quote(S.sendQuote);
    if (q.total > S.balance) {
      flash("error", "Not enough balance for that amount plus fees.");
      return;
    }
    S.balance -= q.total;
    S.activity.unshift({
      kind: "withdrawal", dir: "out", amount: q.amount,
      status: q.amount > 200000 ? "queued" : "confirmed",
      conf: 0, who: "bc1qrecipient…8e21", when: "just now",
      txid: q.amount > 200000 ? null : "3b7d9f1a5c2e4068b1d3f5a7092c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a80"
    });
    S.sendQuote = null;
    el("v-send-amount").value = "";
    el("v-send-usd").textContent = "";
    renderSend();
    flash("success", q.amount > 200000
      ? "Withdrawal submitted and held for approval — it is above the automatic limit. The amount is on hold."
      : "Sent " + btc(q.amount) + " BTC. The transaction is on its way.");
    go("activity");
    renderAll();
  }

  function signupDemo() {
    S.logins.unshift({ kind: "login_ok", ip: "203.0.113.24", when: "just now", ok: true });
    flash("info", "This is a static demo — there is no backend to sign up to.");
    renderSecurity();
  }

  /* ---------------------------------------------------------------- routing */
  function go(view) {
    S.view = view;
    document.querySelectorAll(".view").forEach(function (v) {
      v.classList.toggle("on", v.id === "view-" + view);
    });
    document.querySelectorAll("nav.tabs a").forEach(function (a) {
      a.classList.toggle("on", a.getAttribute("data-go") === view);
    });
    el("url-pill").textContent = "vault.local/" + (view === "wallet" ? "wallet" : view);
    if (view === "admin") goAdmin(S.adminTab);
    renderAll();
  }

  function goAdmin(tab) {
    S.adminTab = tab;
    document.querySelectorAll("[data-admin-tab]").forEach(function (a) {
      a.classList.toggle("on", a.getAttribute("data-admin-tab") === tab);
    });
    document.querySelectorAll(".admin-pane").forEach(function (p) {
      p.classList.toggle("hide", p.id !== "admin-" + tab);
    });
    if (tab === "users") renderAdminUsers();
    if (tab === "user") renderAdminUser();
  }

  /* ---------------------------------------------------------------- wiring */
  function wire() {
    document.addEventListener("click", function (ev) {
      var nav = ev.target.closest("[data-go]");
      if (nav) { ev.preventDefault(); go(nav.getAttribute("data-go")); return; }

      var tab = ev.target.closest("[data-admin-tab]");
      if (tab) { ev.preventDefault(); goAdmin(tab.getAttribute("data-admin-tab")); return; }

      var open = ev.target.closest("[data-open-user]");
      if (open) {
        S.openUser = parseInt(open.getAttribute("data-open-user"), 10);
        goAdmin("user");
        return;
      }

      var act = ev.target.closest("[data-act]");
      if (act) { applyAdminAction(act.getAttribute("data-act")); return; }

      var copy = ev.target.closest("[data-copy]");
      if (copy) {
        var value = copy.getAttribute("data-copy");
        if (navigator.clipboard) {
          navigator.clipboard.writeText(value).then(function () { toast("Copied"); });
        } else { toast("Copied (hold to select)"); }
        return;
      }

      var tier = ev.target.closest("[data-tier]");
      if (tier) {
        S.tier = tier.getAttribute("data-tier");
        document.querySelectorAll("[data-tier]").forEach(function (r) {
          r.classList.toggle("sel", r === tier);
        });
        if (S.sendQuote) renderSend();
        return;
      }

      if (ev.target.closest("[data-reset]")) { seed(); go("wallet"); flash("info", "Demo data reset."); return; }
      if (ev.target.closest("[data-approve]")) {
        flash("success", "Withdrawal approved and broadcast — the amount leaves the queue.");
        S.activity.forEach(function (a) { if (a.status === "queued") { a.status = "confirmed"; a.conf = 1; } });
        renderAll();
        return;
      }
      if (ev.target.closest("[data-reject]")) {
        S.activity.forEach(function (a) {
          if (a.status === "queued") { a.status = "rejected"; a.who = "returned to balance"; }
        });
        flash("warning", "Withdrawal rejected — the held amount is returned to the user's balance.");
        renderAll();
        return;
      }
      if (ev.target.closest("[data-signup]")) { ev.preventDefault(); signupDemo(); return; }
      if (ev.target.closest("[data-2fa]")) {
        if (S.totp) {
          S.totp = false;
          flash("warning", "Two-factor authentication disabled. Your balance is protected by a password alone.");
        } else {
          S.totp = true;
          flash("success", "Two-factor authentication is on. Save your backup codes — they are shown once.");
        }
        S.users[2].totp = S.totp;   // keep the signed-in user in sync with the admin list
        renderAll();
        return;
      }

      var filter = ev.target.closest("[data-filter]");
      if (filter) {
        S.filter = filter.getAttribute("data-filter");
        document.querySelectorAll("[data-filter]").forEach(function (b) {
          b.classList.toggle("on", b === filter);
          b.className = "btn sm " + (b === filter ? "primary" : "ghost");
        });
        renderActivity();
        return;
      }
    });

    el("v-send-quote").addEventListener("click", function () {
      var addr = el("v-send-address").value.trim();
      var raw = el("v-send-amount").value.trim();
      if (!/^(bc1|tb1)[a-z0-9]{20,}$/.test(addr)) {
        flash("error", "That does not look like a valid address for this network.");
        return;
      }
      var amt = Math.round(parseFloat(raw) * 1e8);
      if (!amt || amt < 10000) {
        flash("error", "Enter an amount of at least 0.00010000 BTC (the minimum withdrawal).");
        return;
      }
      if (amt > S.balance) {
        flash("error", "That is more than your balance.");
        return;
      }
      S.sendQuote = amt;
      renderSend();
      el("v-send-review").scrollIntoView({ block: "nearest" });
    });

    el("v-send-confirm").addEventListener("click", confirmSend);

    el("v-send-amount").addEventListener("input", function () {
      var raw = this.value.trim().replace(/,/g, "");
      if (!/^\d*(\.\d{0,8})?$/.test(raw) || raw === "" || raw === ".") {
        el("v-send-usd").textContent = ""; return;
      }
      el("v-send-usd").textContent = "≈ " + usd(Math.round(parseFloat(raw) * 1e8));
    });

    el("v-receive-new").addEventListener("click", function () {
      var tail = Math.random().toString(36).slice(2, 10);
      S.address = "tb1qdemox" + tail + "0example0address0notreal00";
      el("v-receive-address").textContent = S.address;
      el("v-receive-copy").setAttribute("data-copy", S.address);
      toast("New deposit address (demo)");
    });

    el("a-filter").addEventListener("change", renderAdminUsers);

    window.addEventListener("hashchange", function () {
      var v = location.hash.replace("#", "");
      if (v) go(v);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    seed();
    wire();
    var start = location.hash.replace("#", "");
    go(VIEWS.indexOf(start) >= 0 ? start : "wallet");
    // a view name in the hash is a shareable deep link — bring the frame into view
    if (VIEWS.indexOf(start) >= 0 && el("demo")) {
      el("demo").scrollIntoView({ block: "start" });
    }
  });
})();
