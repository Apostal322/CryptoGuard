// Local review app. Text is rendered with textContent only; the page holds no data until
// /api/state answers, and that answer contains only the blinded sheet and this
// reviewer's own decisions.
"use strict";

const DECISIONS = [
  ["confirmed_poisoning_attempt", "Confirmed poisoning attempt"],
  ["likely_poisoning_attempt", "Likely poisoning attempt"],
  ["confirmed_legitimate_interaction", "Confirmed legitimate interaction"],
  ["insufficient_evidence", "Insufficient evidence"],
  ["conflicting_evidence", "Conflicting evidence"],
];
const CHOICES = {
  evidence: [["not_loaded", "not looked at"], ["observed", "observed"],
    ["not_observed", "looked for, absent"], ["not_available", "data not available"],
    ["not_applicable", "not applicable"], ["contradictory", "contradictory"]],
  exposure: [["unsure", "unsure"], ["no", "no"], ["yes", "yes"]],
  confidence: [["medium", "medium"], ["high", "high"], ["low", "low"]],
  token: [["unknown", "unknown"], ["genuine", "genuine token"],
    ["imitation", "imitation contract"], ["not_applicable", "not applicable"]],
  value_class: [["unknown", "unknown"], ["zero", "zero"], ["dust", "dust"],
    ["ordinary", "ordinary"]],
  initiator: [["unknown", "unknown"], ["wallet", "the wallet"],
    ["third_party", "a third party"]],
};
const REASONS = [
  ["lookalike_of_earlier_counterparty", "Look-alike of an earlier counterparty"],
  ["imitation_token_contract", "Imitation token contract"],
  ["zero_value_transfer", "Zero-value transfer"],
  ["dust_value", "Dust value"],
  ["third_party_initiated_transfer", "Initiated by a third party"],
  ["wallet_initiated_transfer", "Initiated by the wallet"],
  ["known_relationship", "Known relationship"],
  ["same_owner_evidence", "Same-owner evidence"],
  ["ordinary_payment_pattern", "Ordinary payment pattern"],
  ["no_earlier_counterparty_found", "No earlier counterparty found"],
  ["history_unavailable", "History unavailable"],
  ["contradictory_observations", "Contradictory observations"],
  ["other", "Other (explain)"],
];
const STATUS_TEXT = {
  complete_for_declared_scope: ["ok", "Complete for the recorded window"],
  partial_history: ["warn", "No earlier rows of this wallet are available locally"],
  source_selected_rows_only: ["warn", "Only rows a research dataset kept: ordinary activity is missing"],
  missing_transaction_details: ["warn", "The listed transaction is not in the local data"],
  missing_receipt: ["warn", "Receipt not recorded"],
  unknown_signer: ["warn", "Signer not recorded"],
  unknown_token_legitimacy: ["warn", "Token not on the reviewed list (unknown, not necessarily fake)"],
  unsupported_contract_execution: ["warn", "Contract execution not interpretable offline"],
  insufficient_evidence: ["warn", "No local evidence"],
  same_block_order_unknown: ["warn", "Other transfers in the same block; their order is unknown"],
};
const FACTS = [
  ["wallet", "Wallet"],
  ["address_under_review", "Address under review"],
  ["transaction", "Transaction"],
  ["block", "Block (observation cutoff)"],
];

// The token arrives in the URL fragment; it is kept for this tab only (so a refresh works)
// and removed from the address bar.
const token = (() => {
  const fromUrl = new URLSearchParams(location.hash.slice(1)).get("token");
  try {
    if (fromUrl) sessionStorage.setItem("cg-review-token", fromUrl);
    return fromUrl || sessionStorage.getItem("cg-review-token") || "";
  } catch {
    return fromUrl || "";
  }
})();
history.replaceState(null, "", location.pathname);
let state = null;
let index = 0;
let dirty = false;

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
};

function banner(msg, kind = "error") {
  const b = $("#banner");
  b.textContent = msg;
  b.className = kind;
  b.hidden = !msg;
}

async function api(path, body) {
  const opts = { headers: { "X-Review-Token": token } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new Error("the review server is not reachable; your form is kept, try again");
  }
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function draftKey(item) {
  return `cg-review:${state.reviewer}:${state.sample}:${item}`;
}
function readDraft(item) {
  try { return JSON.parse(localStorage.getItem(draftKey(item)) || "null"); } catch { return null; }
}
function writeDraft(item, fields) {
  try { localStorage.setItem(draftKey(item), JSON.stringify(fields)); } catch { /* optional */ }
}
function clearDraft(item) {
  try { localStorage.removeItem(draftKey(item)); } catch { /* optional */ }
}

function saved(item) {
  return state.decisions[String(item)];
}

function renderList() {
  const ol = $("#items");
  ol.replaceChildren();
  state.items.forEach((it, i) => {
    const li = el("li");
    const b = el("button", `#${it.item}`, saved(it.item) ? "done" : "");
    b.type = "button";
    b.setAttribute("aria-current", i === index ? "true" : "false");
    b.setAttribute("aria-label", `Item ${it.item}, ${saved(it.item) ? "saved" : "no decision yet"}`);
    b.addEventListener("click", () => go(i));
    li.append(b);
    ol.append(li);
  });
  const n = state.items.filter((it) => saved(it.item)).length;
  $("#progress").textContent = state.finalized
    ? `Finalized: ${n} of ${state.items.length} decisions submitted`
    : `${n} of ${state.items.length} saved`;
  $("#finalize").disabled = state.finalized || n !== state.items.length;
}

function copyButton(value) {
  const b = el("button", "Copy", "copy");
  b.type = "button";
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(String(value)); b.textContent = "Copied"; }
    catch { b.textContent = "Select and copy"; }
    setTimeout(() => { b.textContent = "Copy"; }, 1500);
  });
  return b;
}

function fill(select, kind) {
  for (const [v, label] of CHOICES[kind]) select.append(new Option(label, v));
}

function formFields(form) {
  const f = new FormData(form);
  const num = (k) => (f.get(k) === "" || f.get(k) === null ? null : Number(f.get(k)));
  const it = state.items[index];
  const addr = (f.get("prior_counterparty_address") || "").trim();
  return {
    item: it.item,
    victim_event_id: it.victim_event_id,
    decision: f.get("decision"),
    confidence: f.get("confidence"),
    planting_transfer: f.get("planting_transfer"),
    prior_counterparty: f.get("prior_counterparty"),
    prior_counterparty_address: addr || null,
    matched_leading: num("matched_leading"),
    matched_trailing: num("matched_trailing"),
    token: f.get("token"),
    value_class: f.get("value_class"),
    initiator: f.get("initiator"),
    legitimate_explanation: f.get("legitimate_explanation"),
    used_explorer: f.get("used_explorer") === "on",
    viewed_after_cutoff: f.get("viewed_after_cutoff"),
    saw_external_label: f.get("saw_external_label"),
    saw_source_or_model_output: f.get("saw_source_or_model_output") === "on",
    rationale: (f.get("rationale") || "").trim(),
    notes: (f.get("notes") || "").trim(),
    used_offline_evidence: f.get("used_offline_evidence") === "on",
    saw_later_victim_payment: f.get("saw_later_victim_payment"),
    third_party_label_influenced: f.get("third_party_label_influenced"),
    reason_codes: f.getAll("reason_codes"),
    evidence_refs: (f.get("evidence_refs") || "").split(/\s+/).filter(Boolean),
  };
}

function setFields(form, v) {
  for (const box of form.querySelectorAll('input[name="reason_codes"]')) {
    box.checked = (v.reason_codes || []).includes(box.value);
  }
  for (const [k, val] of Object.entries(v)) {
    if (k === "reason_codes") continue;
    if (k === "evidence_refs") {
      form.elements.namedItem("evidence_refs").value = (val || []).join("\n");
      continue;
    }
    const input = form.elements.namedItem(k);
    if (!input || k === "decision") continue;
    if (input.type === "checkbox") input.checked = Boolean(val);
    else input.value = val === null || val === undefined ? "" : String(val);
  }
  for (const r of form.querySelectorAll('input[name="decision"]')) r.checked = r.value === v.decision;
}

function matchCounts(a, b) {
  const x = a.toLowerCase().slice(2), y = b.toLowerCase().slice(2);
  let lead = 0, trail = 0;
  while (lead < 40 && x[lead] === y[lead]) lead++;
  while (trail < 40 && x[39 - trail] === y[39 - trail]) trail++;
  return [lead, trail];
}

function table(headers, rows) {
  const t = el("table");
  const head = el("tr");
  for (const h of headers) head.append(el("th", h));
  t.append(head);
  for (const r of rows) {
    const tr = el("tr");
    for (const cell of r) {
      const td = el("td");
      if (typeof cell === "string" && cell.startsWith("0x")) td.append(el("code", cell));
      else td.textContent = cell === null || cell === undefined ? "unknown" : String(cell);
      tr.append(td);
    }
    t.append(tr);
  }
  return t;
}

function renderEvidence(box, ev) {
  if (!ev) return;
  box.hidden = false;
  box.append(el("h3", `Offline evidence before block ${ev.cutoff.block}`));
  box.append(el("p", ev.coverage.explanation, "muted"));
  const chips = el("ul", undefined, "chips");
  for (const s of ev.coverage.statuses) {
    const [kind, text] = STATUS_TEXT[s] || ["warn", s];
    chips.append(el("li", text, kind));
  }
  box.append(chips);
  const row = (r) => [r.block, r.transaction, r.token, r.from, r.to, r.value_base_units];
  const heads = ["Block", "Transaction", "Token", "From", "To", "Value (base units)"];
  box.append(el("h4", "1. Candidate event"));
  if (ev.candidate_event.length) {
    box.append(table([...heads, "Direction"], ev.candidate_event.map((r) => [...row(r), r.direction])));
  } else {
    box.append(el("p", "Not in the local data.", "warn"));
  }
  const sem = ev.transaction_semantics;
  const signer = Array.isArray(sem.signer) ? sem.signer.join(", ") : sem.signer;
  box.append(el("h4", "2. Transaction semantics"));
  box.append(table(["Execution", "Signer", "Zero value"], [[sem.execution, signer, sem.zero_value]]));
  box.append(el("h4", "3. Token"));
  box.append(table(["Token", "On the reviewed list"],
    ev.token_provenance.map((t) => [t.token, t.on_reviewed_token_list ? "yes" : "unknown"])));
  box.append(el("h4", "4. Address relationship"));
  const rel = ev.address_relationship;
  box.append(el("p", `Between the wallet and this address: ${rel.interpretation || rel.earlier_rows_between_wallet_and_address + " earlier row(s)"}. ${rel.note}.`));
  const hist = ev.wallet_history;
  const d = el("details");
  const same = hist.same_block_rows_order_unknown ? `; ${hist.same_block_rows_order_unknown} more in the same block, order unknown (not shown)` : "";
  d.append(el("summary", `5. Wallet history before the cutoff: ${hist.rows_before_cutoff} row(s), showing the last ${hist.shown.length}${same}`));
  if (hist.shown.length) d.append(table(heads, hist.shown.map(row)));
  box.append(d);
  if (ev.graph_context) {
    const g = ev.graph_context;
    box.append(el("h4", "6. This address with other wallets before the cutoff"));
    box.append(el("p", `${g.earlier_rows_of_address_with_other_wallets} row(s) with ${g.distinct_other_wallets} other wallet(s) in the local data.`));
  }
}

function go(i) {
  if (dirty && !confirm("This item has unsaved changes (kept as a draft in this browser). Leave it?")) return;
  index = Math.max(0, Math.min(state.items.length - 1, i));
  render();
}

function render() {
  dirty = false;
  renderList();
  const it = state.items[index];
  const section = $("#item");
  const frag = $("#form-template").content.cloneNode(true);
  $(".item-title", frag).textContent = `Item ${it.item} of ${state.items.length}`;
  $(".cutoff", frag).textContent =
    `Judge the planting with evidence up to block ${it.block}. If you look at later activity ` +
    "(an explorer shows it), record that below; it is not hidden from you, only from this sheet.";
  if (it.description) $(".item-title", frag).textContent = `${it.description}: item ${it.item} of ${state.items.length}`;
  const dl = $(".facts", frag);
  for (const [k, label] of FACTS) {
    const dd = el("dd");
    dd.append(el("code", it[k]));
    dd.append(copyButton(it[k]));
    dl.append(el("dt", label), dd);
  }
  renderEvidence($(".evidence", frag), it.evidence);
  const card = $(".card", frag);
  if (it.coverage_note) card.append(el("p", it.coverage_note, "coverage"));
  if (Array.isArray(it.context) && it.context.length) {
    const details = el("details", undefined, "context");
    details.append(el("summary", `Recorded wallet activity before the cutoff (last ${it.context.length})`));
    const table = el("table");
    const head = el("tr");
    for (const h of ["Block", "Direction", "Counterparty", "Value (base units)"]) head.append(el("th", h));
    table.append(head);
    for (const row of it.context) {
      const tr = el("tr");
      tr.append(el("td", row.block), el("td", row.direction));
      const td = el("td"); td.append(el("code", row.counterparty)); tr.append(td);
      tr.append(el("td", row.value));
      table.append(tr);
    }
    details.append(table);
    card.append(details);
  }
  const form = $("form", frag);
  const fs = $(".decision", form);
  DECISIONS.forEach(([v, label], n) => {
    const l = el("label", undefined, "radio");
    const r = el("input");
    r.type = "radio"; r.name = "decision"; r.value = v; r.required = true;
    l.append(r, el("span", `${n + 1}. ${label}`));
    fs.append(l);
  });
  for (const s of form.querySelectorAll("select")) fill(s, s.dataset.kind || s.name);
  const reasons = $(".reasons", form);
  for (const [v, label] of REASONS) {
    const l = el("label", undefined, "check");
    const box = el("input");
    box.type = "checkbox"; box.name = "reason_codes"; box.value = v;
    l.append(box, el("span", label));
    reasons.append(l);
  }
  const current = saved(it.item);
  const draft = readDraft(it.item);
  if (current) setFields(form, current);
  if (draft) { setFields(form, draft); dirty = true; }
  const status = $(".status", form);
  status.textContent = current
    ? `Saved revision ${current.revision} at ${current.saved_at}` + (draft ? " · unsaved draft restored" : "")
    : draft ? "Unsaved draft restored" : "No decision saved yet";
  const addr = form.elements.namedItem("prior_counterparty_address");
  addr.addEventListener("change", () => {
    const v = addr.value.trim();
    if (/^0x[0-9a-fA-F]{40}$/.test(v)) {
      const [lead, trail] = matchCounts(v, it.address_under_review);
      form.elements.namedItem("matched_leading").value = lead;
      form.elements.namedItem("matched_trailing").value = trail;
    }
  });
  form.addEventListener("input", () => {
    dirty = true;
    writeDraft(it.item, formFields(form));
    status.textContent = "Unsaved changes";
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await save(form, status);
  });
  $(".prev", form).addEventListener("click", () => go(index - 1));
  $(".next", form).addEventListener("click", () => go(index + 1));
  if (state.finalized) for (const x of form.elements) x.disabled = true;
  section.replaceChildren(frag);
}

async function save(form, status) {
  if (state.finalized) return;
  const fields = formFields(form);
  if (!fields.decision) { status.textContent = "Choose a decision (1–5) first"; return; }
  const before = saved(fields.item);
  status.textContent = "Saving…";
  try {
    const res = await api("/api/save", { fields, expected_revision: before ? before.revision : 0 });
    state.decisions[String(fields.item)] = res.saved;
    clearDraft(fields.item);
    dirty = false;
    banner("");
    status.textContent = `Saved revision ${res.saved.revision} at ${res.saved.saved_at}`;
    renderList();
  } catch (err) {
    status.textContent = "Not saved";
    banner(`Not saved: ${err.message}. Your input is kept as a draft in this browser.`);
  }
}

async function finalize() {
  const n = state.items.length;
  if (!confirm(`Finalize all ${n} decisions? After this, nothing can be changed without a protocol amendment.`)) return;
  try {
    const res = await api("/api/finalize", {});
    banner(`Finalized. Submission hash ${res.content_sha256}. Send submission.json to the maintainer.`, "ok");
    state = await api("/api/state");
    render();
  } catch (err) {
    banner(`Not finalized: ${err.message}`);
  }
}

document.addEventListener("keydown", (e) => {
  if (!state) return;
  const form = $("#item form");
  const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
    e.preventDefault();
    if (form) form.requestSubmit();
    return;
  }
  if (typing) return;
  if (e.key === "[") go(index - 1);
  else if (e.key === "]") go(index + 1);
  else if (/^[1-5]$/.test(e.key) && form && !state.finalized) {
    const r = form.querySelectorAll('input[name="decision"]')[Number(e.key) - 1];
    r.checked = true;
    r.dispatchEvent(new Event("input", { bubbles: true }));
  }
});
window.addEventListener("beforeunload", (e) => { if (dirty) e.preventDefault(); });

(async () => {
  $("#finalize").addEventListener("click", finalize);
  if (!token) { banner("Open the exact URL printed by `cryptoguard ml review serve` (it carries a session token)."); return; }
  try {
    state = await api("/api/state");
  } catch (err) {
    banner(`Cannot load the review: ${err.message}`);
    return;
  }
  $("#who").textContent = `Reviewer ${state.reviewer} · sample ${state.sample} · ${state.protocol}`;
  const first = state.items.findIndex((it) => !saved(it.item));
  index = first < 0 ? 0 : first;
  if (state.finalized) banner("This submission is finalized and read-only.", "ok");
  render();
})();
