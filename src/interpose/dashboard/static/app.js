"use strict";

// Interpose dashboard. All data is inserted with textContent through h(); nothing
// from the server is ever parsed as HTML.

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const app = { csrf: "", data: null, audit: [], view: "secrets", secretFilter: "all", activityFilter: "all" };

// ---------- helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value === null || value === undefined) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

async function api(method, path, body) {
  const options = { method, headers: { "X-Interpose-CSRF": app.csrf }, credentials: "same-origin" };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  if (response.status === 401) {
    location.reload();
    throw new Error("Session expired");
  }
  const payload = response.headers.get("content-type")?.includes("json") ? await response.json() : null;
  if (!response.ok) {
    const detail = payload?.detail;
    const message = Array.isArray(detail)
      ? detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("\n")
      : detail || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload;
}

function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), isError ? 5000 : 2400);
}

function relativeTime(iso) {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString();
}

const shortRef = (reference) => reference.replace(/^secret:\/\//, "");
const scopeBadge = (scope) => h("span", { class: `badge ${scope}` }, scope === "project" ? "Project" : "Global");
const hasProject = () => Boolean(app.data?.project);

function confirmAction(title, body, okLabel = "Delete") {
  const dialog = document.getElementById("confirm-dialog");
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-body").textContent = body;
  document.getElementById("confirm-ok").textContent = okLabel;
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
  });
}

function empty(title, text, action) {
  return h("div", { class: "empty" }, h("strong", {}, title), h("div", {}, text), action ? h("div", { style: "margin-top:12px" }, action) : null);
}

// ---------- data ----------

async function refresh() {
  app.data = await api("GET", "/api/state");
  renderChrome();
  render();
}

async function refreshAudit() {
  app.audit = await api("GET", "/api/audit?limit=200");
  if (app.view === "activity") render();
}

function effectiveFor(reference) {
  return app.data.effective.find((entry) => entry.reference === reference);
}

// ---------- chrome ----------

function renderChrome() {
  const chip = document.getElementById("project-chip");
  const project = app.data.project;
  chip.classList.toggle("none", !project);
  chip.textContent = project ? `Project · ${project.name}` : "No project · global only";
  chip.title = project ? project.root : app.data.working_directory;
  const proxyUrl = new URL(app.data.proxy_url);
  document.getElementById("proxy-label").textContent = `Proxy · ${proxyUrl.host}`;
  document.getElementById("proxy-status").title = app.data.proxy_url;
  for (const item of document.querySelectorAll(".nav-item")) {
    item.classList.toggle("active", item.dataset.view === app.view);
  }
}

function projectBanner() {
  if (hasProject()) return null;
  return h("div", { class: "banner" },
    h("p", {},
      h("strong", {}, "This folder isn't a registered project. "),
      "Register ", h("code", {}, app.data.working_directory),
      " to keep secrets and policies that only apply here."),
    h("button", { class: "btn primary", onclick: registerProject }, "Register as project"));
}

async function registerProject() {
  try {
    const project = await api("POST", "/api/project", {});
    toast(`Registered project "${project.name}"`);
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
}

// ---------- views ----------

function render() {
  const content = document.getElementById("content");
  const views = { secrets: renderSecrets, policies: renderPolicies, activity: renderActivity, connect: renderConnect };
  content.replaceChildren(...[].concat(views[app.view]()).filter(Boolean));
}

function renderSecrets() {
  const filter = app.secretFilter;
  const rows = app.data.secrets.filter((s) => filter === "all" || s.scope === filter);
  const projectRefs = new Set(app.data.secrets.filter((s) => s.scope === "project").map((s) => s.reference));

  const head = h("div", { class: "page-head" },
    h("h1", {}, "Secrets"),
    segmented(["all", "project", "global"], filter, (value) => { app.secretFilter = value; render(); },
      { all: "All", project: "Project", global: "Global" }),
    h("div", { class: "spacer" }),
    h("button", { class: "btn primary", onclick: () => openSecretDialog() }, "+ Add secret"));

  if (!rows.length) {
    return [projectBanner(), head, h("div", { class: "grid-wrap" },
      empty("No secrets yet", "Add one and the agent can reference it as secret://provider/name.",
        h("button", { class: "btn primary", onclick: () => openSecretDialog() }, "Add secret")))];
  }

  const table = h("table", { class: "grid" },
    h("thead", {}, h("tr", {}, ["Reference", "Scope", "Resolution", "Policy", "Fingerprint", "Updated", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((secret) => {
      const effective = effectiveFor(secret.reference);
      const overridden = secret.scope === "global" && projectRefs.has(secret.reference);
      const resolution = overridden
        ? h("span", { class: "badge neutral", title: "A project secret with the same reference takes precedence here" }, "Overridden by project")
        : secret.scope === "project" && app.data.secrets.some((s) => s.scope === "global" && s.reference === secret.reference)
          ? h("span", { class: "badge project" }, "Overrides global")
          : h("span", { class: "badge ok" }, "Active");
      const policy = effective?.policy_from
        ? h("span", {}, scopeBadge(effective.policy_from), h("span", { class: "note" }, "policy"))
        : h("span", { class: "badge warn", title: "Requests using this secret are denied until a policy exists" }, "No policy — denied");
      return h("tr", {},
        h("td", { class: `mono ${overridden ? "strike" : ""}` }, shortRef(secret.reference)),
        h("td", {}, scopeBadge(secret.scope)),
        h("td", {}, resolution),
        h("td", {}, policy),
        h("td", { class: "mono muted", title: "HMAC fingerprint — not reversible" }, secret.fingerprint),
        h("td", { class: "muted", title: secret.updated_at }, relativeTime(secret.updated_at)),
        h("td", { class: "actions" },
          h("button", { class: "btn link", onclick: () => openPolicyDialog({ secret: secret.reference, scope: effective?.policy_from || secret.scope }) },
            effective?.policy_from ? "Edit policy" : "Add policy"),
          h("button", { class: "btn link", onclick: () => openSecretDialog(secret) }, "Replace value"),
          h("button", { class: "btn link danger-text", onclick: () => deleteSecret(secret) }, "Delete")));
    })));

  return [projectBanner(), head,
    h("p", { class: "lead" }, "Agents only ever see the reference. Inside this project a reference resolves to the project value first, then the global one."),
    h("div", { class: "grid-wrap" }, table)];
}

function segmented(values, active, onChange, labels) {
  return h("div", { class: "segmented", role: "tablist" }, values.map((value) =>
    h("button", { class: value === active ? "active" : "", role: "tab", "aria-selected": String(value === active), onclick: () => onChange(value) }, labels[value])));
}

async function deleteSecret(secret) {
  const ok = await confirmAction("Delete secret?",
    `${shortRef(secret.reference)} (${secret.scope}) will be removed from the vault. Requests that use it will fail.`);
  if (!ok) return;
  try {
    await api("DELETE", `/api/secrets?scope=${secret.scope}&reference=${encodeURIComponent(secret.reference)}`);
    toast("Secret deleted");
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderPolicies() {
  const head = h("div", { class: "page-head" },
    h("h1", {}, "Policies"),
    h("div", { class: "spacer" }),
    h("button", { class: "btn primary", onclick: () => openPolicyDialog({}) }, "+ Add policy"));
  const intro = h("p", { class: "lead" }, "A policy says where a secret may be sent. With no policy, every use is denied. A project policy overrides the global one inside this project.");

  if (!app.data.policies.length) {
    return [projectBanner(), head, intro, h("div", { class: "grid-wrap" },
      empty("No policies yet", "Secrets without a policy cannot be used.",
        h("button", { class: "btn primary", onclick: () => openPolicyDialog({}) }, "Add policy")))];
  }

  const sections = [];
  for (const scope of ["project", "global"]) {
    const policies = app.data.policies.filter((p) => p.scope === scope);
    if (!policies.length) continue;
    const overridden = (p) => scope === "global" && app.data.policies.some((o) => o.scope === "project" && o.secret === p.secret);
    sections.push(h("h2", { class: "section-title" }, scope === "project" ? `Project · ${app.data.project.name}` : "Global"));
    sections.push(h("div", { class: "cards" }, policies.map((p) => policyCard(p, overridden(p)))));
  }
  return [projectBanner(), head, intro, ...sections];
}

function chips(values, fallback) {
  if (!values.length) return h("span", { class: "muted" }, fallback);
  return h("div", { class: "chips" }, values.map((v) => h("span", { class: "chip" }, v)));
}

function policyCard(policy, overridden) {
  const location = policy.inject.map((slot) => `${slot.kind}: ${slot.name}`);
  return h("article", { class: "card" },
    h("div", { class: "card-head" },
      h("h3", { title: policy.secret }, shortRef(policy.secret)),
      scopeBadge(policy.scope),
      overridden ? h("span", { class: "badge neutral" }, "Overridden here") : null,
      h("div", { class: "spacer" }),
      h("button", { class: "btn link", onclick: () => openPolicyDialog(policy) }, "Edit"),
      h("button", { class: "btn link danger-text", onclick: () => deletePolicy(policy) }, "Delete")),
    h("dl", { class: "kv" },
      h("dt", {}, "Hosts"), h("dd", {}, chips(policy.hosts, "none")),
      h("dt", {}, "Methods"), h("dd", {}, chips(policy.methods, "any")),
      h("dt", {}, "Paths"), h("dd", {}, chips(policy.paths, "any")),
      h("dt", {}, "Credential in"), h("dd", {}, chips(location, "—"),
        policy.inject_is_default ? h("span", { class: "note" }, "default") : null),
      policy.schemes.includes("http") ? [h("dt", {}, "Plain HTTP"), h("dd", {}, h("span", { class: "badge warn" }, "allowed"))] : null,
      policy.allow_exec ? [h("dt", {}, "interpose-exec"), h("dd", {}, h("span", { class: "badge danger" }, "allowed"))] : null));
}

async function deletePolicy(policy) {
  const ok = await confirmAction("Delete policy?",
    `${shortRef(policy.secret)} (${policy.scope}) will fall back to ${policy.scope === "project" ? "the global policy, if any" : "no policy — every use will be denied"}.`);
  if (!ok) return;
  try {
    await api("DELETE", `/api/policies/${policy.id}`);
    toast("Policy deleted");
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderActivity() {
  const filters = { all: "All", deny: "Denied", allow: "Allowed", admin: "Changes" };
  const rows = app.audit.filter((e) =>
    app.activityFilter === "all" ? true
      : app.activityFilter === "admin" ? e.action.startsWith("ADMIN_")
        : e.result === app.activityFilter);
  const head = h("div", { class: "page-head" },
    h("h1", {}, "Activity"),
    segmented(Object.keys(filters), app.activityFilter, (value) => { app.activityFilter = value; render(); }, filters),
    h("div", { class: "spacer" }),
    h("span", { class: "muted" }, "Live · refreshes every 3 s"));
  if (!rows.length) {
    return [head, h("div", { class: "grid-wrap" }, empty("Nothing here yet", "Requests through the proxy and changes made here appear as they happen."))];
  }
  const resultBadge = (entry) => {
    if (entry.result === "deny") return h("span", { class: "badge danger" }, "Denied");
    if (entry.result === "allow") return h("span", { class: "badge ok" }, "Allowed");
    return h("span", { class: "badge neutral" }, entry.action.startsWith("ADMIN_") ? "Change" : entry.result);
  };
  const table = h("table", { class: "grid" },
    h("thead", {}, h("tr", {}, ["Time", "Result", "Action", "Reference", "Destination", "Status", "Detail"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((entry) => h("tr", {},
      h("td", { class: "muted", title: entry.timestamp }, new Date(entry.timestamp).toLocaleTimeString()),
      h("td", {}, resultBadge(entry)),
      h("td", { class: "mono" }, entry.action),
      h("td", { class: "mono" }, entry.reference === "none" ? "—" : shortRef(entry.reference)),
      h("td", { class: "mono" }, entry.destination),
      h("td", {}, entry.status),
      h("td", { class: "wrap muted" }, [entry.reason, entry.location ? `in ${entry.location}` : null].filter(Boolean).join(" · "))))));
  return [head, h("div", { class: "grid-wrap" }, table)];
}

function envNameFor(reference) {
  const provider = shortRef(reference).split("/")[0].replace(/[^a-z0-9]+/gi, "_").toUpperCase();
  return { key: `${provider}_API_KEY`, base: `${provider}_BASE_URL` };
}

function snippet(title, text) {
  return h("div", { class: "snippet" },
    h("div", { class: "snippet-head" }, h("span", {}, title), h("div", { class: "spacer" }),
      h("button", {
        class: "btn small", onclick: async () => {
          try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed", true); }
        },
      }, "Copy")),
    h("pre", {}, text));
}

function renderConnect() {
  const ready = app.data.effective.filter((e) => e.ready);
  const proxy = app.data.proxy_url.replace(/\/$/, "");
  const head = h("div", { class: "page-head" }, h("h1", {}, "Connect an agent"));
  const intro = h("p", { class: "lead" },
    "Give the agent references and point its base URL at the proxy. Policies decide where each secret may go; the agent never holds a value.");
  if (!ready.length) {
    return [head, intro, h("div", { class: "grid-wrap" },
      empty("Nothing to connect yet", "A secret needs both a value and a policy before an agent can use it."))];
  }
  const env = [];
  const profileEnv = [];
  const profilePublic = [];
  for (const entry of ready) {
    const policy = app.data.policies.find((p) => p.secret === entry.reference && p.scope === entry.policy_from);
    const host = policy?.hosts.find((x) => !x.includes("*")) || policy?.hosts[0] || "api.example.com";
    const names = envNameFor(entry.reference);
    env.push(`${names.key}=${entry.reference}`, `${names.base}=${proxy}/proxy/${host}`, "");
    profileEnv.push(`  ${names.key}: ${entry.reference}`);
    profilePublic.push(`  ${names.base}: ${proxy}/proxy/${host}`);
  }
  const profile = ["version: 1", "", "environment:", ...profileEnv, "", "public_environment:", ...profilePublic, ""].join("\n");
  return [head, intro,
    snippet(".env — references only, safe to commit", env.join("\n").trimEnd() + "\n"),
    snippet("session.yaml — for interpose run", profile),
    snippet("Run an agent with a clean environment", "interpose run --profile session.yaml -- claude\n"),
    h("p", { class: "muted" }, "Variable names are suggestions derived from the provider; rename them to whatever the tool expects.")];
}

// ---------- dialogs ----------

function wireDialogClose(dialog) {
  for (const button of dialog.querySelectorAll("[data-close]")) button.addEventListener("click", () => dialog.close());
}

function openSecretDialog(existing) {
  const dialog = document.getElementById("secret-dialog");
  const form = document.getElementById("secret-form");
  form.reset();
  document.getElementById("secret-error").textContent = "";
  document.getElementById("secret-dialog-title").textContent = existing ? "Replace secret value" : "Add secret";
  const projectRadio = form.querySelector('input[name=scope][value=project]');
  projectRadio.disabled = !hasProject();
  const scope = existing?.scope || (hasProject() ? "project" : "global");
  form.querySelector(`input[name=scope][value=${scope}]`).checked = true;
  form.reference.value = existing ? shortRef(existing.reference) : "";
  form.reference.readOnly = Boolean(existing);
  for (const radio of form.querySelectorAll("input[name=scope]")) radio.disabled = Boolean(existing) || (radio.value === "project" && !hasProject());
  dialog.showModal();
  (existing ? form.value : form.reference).focus();
}

async function submitSecret(event) {
  event.preventDefault();
  const form = event.target;
  const payload = {
    scope: form.querySelector("input[name=scope]:checked").value,
    reference: form.reference.value.trim(),
    value: form.value.value,
  };
  try {
    const saved = await api("POST", "/api/secrets", payload);
    form.value.value = "";
    document.getElementById("secret-dialog").close();
    toast(saved.trimmed ? "Secret stored — spaces at the start or end were removed" : "Secret stored");
    await refresh();
    if (!effectiveFor(saved.reference)?.policy_from) {
      openPolicyDialog({ secret: saved.reference, scope: saved.scope });
    }
  } catch (error) {
    document.getElementById("secret-error").textContent = error.message;
  }
}

function injectRow(kind = "header", name = "") {
  const row = h("div", { class: "inject-row" },
    h("select", { name: "inject-kind", onchange: updateYaml },
      ["header", "query", "form"].map((k) => h("option", { value: k, selected: k === kind }, k))),
    h("input", { name: "inject-name", value: name, spellcheck: "false", placeholder: "Authorization", oninput: updateYaml }),
    h("button", { type: "button", class: "btn small", title: "Remove", onclick: () => { row.remove(); updateYaml(); } }, "✕"));
  return row;
}

function openPolicyDialog(policy) {
  const dialog = document.getElementById("policy-dialog");
  const form = document.getElementById("policy-form");
  form.reset();
  document.getElementById("policy-error").textContent = "";
  form.secret.value = policy.secret ? shortRef(policy.secret) : "";
  form.secret.readOnly = Boolean(policy.id);
  const scope = policy.scope || (hasProject() ? "project" : "global");
  for (const radio of form.querySelectorAll("input[name=scope]")) {
    radio.disabled = radio.value === "project" && !hasProject();
    radio.checked = radio.value === scope;
  }
  form.hosts.value = (policy.hosts || []).join("\n");
  form.paths.value = (policy.paths || []).join("\n");
  const checks = document.getElementById("method-checks");
  checks.replaceChildren(...METHODS.map((m) => h("label", { class: "check" },
    h("input", { type: "checkbox", name: "method", value: m, checked: (policy.methods || []).includes(m), onchange: updateYaml }), m)));
  const rows = document.getElementById("inject-rows");
  // Editing keeps exactly the slots in effect, including the defaults, so saving
  // never silently drops one. A new policy starts with the Authorization header.
  const slots = policy.inject?.length ? policy.inject : [{ kind: "header", name: "Authorization" }];
  rows.replaceChildren(...slots.map((slot) => injectRow(slot.kind, slot.name)));
  form.allow_insecure_http.checked = (policy.schemes || []).includes("http");
  form.allow_exec.checked = Boolean(policy.allow_exec);
  updateYaml();
  dialog.showModal();
  (policy.secret ? form.hosts : form.secret).focus();
}

function policyPayload() {
  const form = document.getElementById("policy-form");
  const lines = (text) => text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const inject = [...document.querySelectorAll("#inject-rows .inject-row")]
    .map((row) => ({ kind: row.querySelector("select").value, name: row.querySelector("input").value.trim() }))
    .filter((slot) => slot.name);
  return {
    scope: form.querySelector("input[name=scope]:checked")?.value || "global",
    secret: form.secret.value.trim(),
    hosts: lines(form.hosts.value),
    paths: lines(form.paths.value),
    methods: [...form.querySelectorAll("input[name=method]:checked")].map((c) => c.value),
    inject,
    allow_insecure_http: form.allow_insecure_http.checked,
    allow_exec: form.allow_exec.checked,
  };
}

function updateYaml() {
  const p = policyPayload();
  const out = [`secret: ${p.secret || "<provider/name>"}`, "", "allow:", "  hosts:", ...(p.hosts.length ? p.hosts : ["<host>"]).map((x) => `    - ${x}`)];
  if (p.methods.length) out.push("", "methods:", ...p.methods.map((m) => `  - ${m}`));
  if (p.paths.length) out.push("", "paths:", ...p.paths.map((x) => `  - ${x}`));
  if (p.inject.length) out.push("", "inject:", ...p.inject.map((s) => `  - ${s.kind}: ${s.name}`));
  if (p.allow_insecure_http) out.push("", "schemes:", "  - https", "  - http");
  if (p.allow_exec) out.push("", "allow_exec: true");
  document.getElementById("yaml-preview").textContent = out.join("\n");
}

async function submitPolicy(event) {
  event.preventDefault();
  const payload = policyPayload();
  if (!payload.inject.length) {
    document.getElementById("policy-error").textContent = "Add at least one credential location.";
    return;
  }
  try {
    await api("POST", "/api/policies", payload);
    document.getElementById("policy-dialog").close();
    toast("Policy saved");
    await refresh();
  } catch (error) {
    document.getElementById("policy-error").textContent = error.message;
  }
}

// ---------- boot ----------

async function boot() {
  for (const dialog of document.querySelectorAll("dialog")) wireDialogClose(dialog);
  document.getElementById("secret-form").addEventListener("submit", submitSecret);
  const policyForm = document.getElementById("policy-form");
  policyForm.addEventListener("submit", submitPolicy);
  policyForm.addEventListener("input", updateYaml);
  document.getElementById("add-inject").addEventListener("click", () => {
    document.getElementById("inject-rows").append(injectRow("header", ""));
    updateYaml();
  });
  for (const item of document.querySelectorAll(".nav-item")) {
    item.addEventListener("click", () => { location.hash = `#/${item.dataset.view}`; });
  }
  const VIEWS = ["secrets", "policies", "activity", "connect"];
  async function route() {
    const requested = location.hash.replace(/^#\//, "");
    app.view = VIEWS.includes(requested) ? requested : "secrets";
    if (!app.data) return;
    renderChrome();
    if (app.view === "activity") await refreshAudit().catch(() => {});
    render();
  }
  window.addEventListener("hashchange", route);

  app.csrf = (await api("GET", "/api/session")).csrf;
  await route();
  await refresh();
  if (app.view === "activity") await refreshAudit();
  setInterval(() => {
    if (document.visibilityState !== "visible") return;
    if (app.view === "activity") refreshAudit().catch(() => {});
  }, 3000);
}

boot().catch((error) => toast(error.message, true));
