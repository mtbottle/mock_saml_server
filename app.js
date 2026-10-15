import * as S from "./saml.js";
import { xmldsig } from "./vendor.js";

const LS_CONFIG = "mocksaml:config";
const LS_KEYS = "mocksaml:keys";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// ---------------------------------------------------------------------------
// State & storage
// ---------------------------------------------------------------------------

function defaultConfig() {
  const base = location.origin + location.pathname.replace(/index\.html$/, "");
  return {
    idpEntityId: base,
    ssoUrl: base + "sso",
    spAcsUrl: "",
    spEntityId: "",
    nameIdFormat: S.NAMEID_FORMATS.persistent,
    authnContextClassRef: S.AUTHN_CONTEXT.pwdProtectedTransport,
    signAssertion: true,
    signResponse: false,
    wantAuthnRequestsSigned: false,
    assertionTtlSeconds: 300,
    sessionTtlSeconds: 3600,
    postTarget: "_self",
    idpDisplayName: "Mock SAML IdP",
  };
}

function loadConfig() {
  try {
    return { ...defaultConfig(), ...JSON.parse(localStorage.getItem(LS_CONFIG) || "{}") };
  } catch {
    return defaultConfig();
  }
}

function saveConfig(config) {
  localStorage.setItem(LS_CONFIG, JSON.stringify(config));
}

function readJSON(key) {
  try {
    return JSON.parse(localStorage.getItem(key) || "null");
  } catch {
    return null;
  }
}

const state = {
  config: loadConfig(),
  keys: null,
  keySource: "",
  lastResponse: null,
  pretty: true,
  request: null,
};

// ---------------------------------------------------------------------------
// Small UI helpers
// ---------------------------------------------------------------------------

let toastTimer;
function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2200);
}

function showTab(name) {
  for (const btn of $$(".tabs button")) btn.classList.toggle("active", btn.dataset.tab === name);
  for (const panel of $$(".tab-panel")) panel.classList.toggle("active", panel.id === `tab-${name}`);
  if (name === "metadata") renderMetadata();
  if (name === "certificate") renderCertificate();
}

function banner(el, kind, html) {
  el.className = `banner banner-${kind}`;
  el.innerHTML = html;
  el.hidden = false;
}

function download(filename, text, type = "application/xml") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Copy failed — select and copy manually");
  }
}

function fillSelect(select, entries) {
  select.innerHTML = "";
  for (const [value, label] of entries) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    select.appendChild(opt);
  }
}

function spkiToPem(base64) {
  const lines = base64.match(/.{1,64}/g)?.join("\n") || base64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`;
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

function setKeyStatus(text, cls = "") {
  const el = $("#key-status");
  el.textContent = text;
  el.className = `key-status ${cls}`;
}

async function ensureKeys() {
  const stored = readJSON(LS_KEYS);
  if (stored?.privateKeyPkcs8) {
    state.keys = stored;
    state.keySource = "browser (localStorage)";
    return;
  }
  try {
    const res = await fetch("./idp-key.json", { cache: "no-store" });
    if (res.ok) {
      const material = await res.json();
      if (material.privateKeyPkcs8 && material.certificateBase64) {
        state.keys = material;
        state.keySource = "bundled demo key";
        return;
      }
    }
  } catch {
    /* ignore, fall through to generating */
  }
  state.keys = await S.generateKeyMaterial();
  localStorage.setItem(LS_KEYS, JSON.stringify(state.keys));
  state.keySource = "generated (localStorage)";
}

async function useDemoKey() {
  localStorage.removeItem(LS_KEYS);
  try {
    const res = await fetch("./idp-key.json", { cache: "no-store" });
    if (!res.ok) throw new Error("idp-key.json not found");
    state.keys = await res.json();
    state.keySource = "bundled demo key";
    updateKeyStatus();
    renderCertificate();
    renderMetadata();
    toast("Loaded bundled demo key");
  } catch (err) {
    toast(err.message);
  }
}

async function regenerateKeys() {
  setKeyStatus("generating…");
  state.keys = await S.generateKeyMaterial(state.config.idpDisplayName || "Mock SAML IdP");
  localStorage.setItem(LS_KEYS, JSON.stringify(state.keys));
  state.keySource = "generated (localStorage)";
  updateKeyStatus();
  renderCertificate();
  renderMetadata();
  toast("New key pair generated");
}

function updateKeyStatus() {
  const thumb = (state.keys.thumbprint || "").slice(0, 16);
  setKeyStatus(`key ready · ${thumb}…`, "ready");
}

// ---------------------------------------------------------------------------
// Attribute rows
// ---------------------------------------------------------------------------

function addAttributeRow(name = "", value = "") {
  const list = $("#attribute-list");
  const row = document.createElement("div");
  row.className = "attr-row";
  row.innerHTML = `
    <input class="attr-name" type="text" placeholder="Attribute name (e.g. department)" value="${name.replace(/"/g, "&quot;")}" />
    <input class="attr-value" type="text" placeholder="Value(s), comma separated" value="${value.replace(/"/g, "&quot;")}" />
    <button type="button" class="btn btn-ghost small remove" title="Remove">✕</button>`;
  row.querySelector(".remove").addEventListener("click", () => row.remove());
  list.appendChild(row);
}

function readAttributeRows() {
  const out = [];
  for (const row of $$("#attribute-list .attr-row")) {
    const name = row.querySelector(".attr-name").value.trim();
    const raw = row.querySelector(".attr-value").value.trim();
    if (!name) continue;
    const values = raw.split(",").map((v) => v.trim()).filter(Boolean);
    out.push({ name, values });
  }
  return out;
}

// ---------------------------------------------------------------------------
// AuthnRequest (SP initiated)
// ---------------------------------------------------------------------------

function parseQuery() {
  const params = new URLSearchParams(location.search);
  return { samlRequest: params.get("SAMLRequest"), relayState: params.get("RelayState") };
}

async function handleIncomingRequest() {
  const { samlRequest, relayState } = parseQuery();
  if (!samlRequest) return;
  try {
    const req = await S.parseSamlRequestParam(samlRequest);
    state.request = req;
    if (req.acsUrl) $("#acs-url").value = req.acsUrl;
    if (req.spEntityId) $("#audience").value = req.spEntityId;
    if (req.id) $("#in-response-to").value = req.id;
    if (relayState) $("#relay-state").value = relayState;
    if (req.nameIdFormat) $("#nameid-format").value = req.nameIdFormat;
    const rows = [];
    rows.push(`SP Entity ID: <code>${escapeHtml(req.spEntityId || "—")}</code>`);
    rows.push(`ACS URL: <code>${escapeHtml(req.acsUrl || "(none in request)")}</code>`);
    rows.push(`InResponseTo: <code>${escapeHtml(req.id || "—")}</code>`);
    if (relayState) rows.push(`RelayState: <code>${escapeHtml(relayState)}</code>`);
    banner(
      $("#request-banner"),
      "info",
      `<strong>SP-initiated login detected.</strong><br />${rows.join("<br />")}`
    );
  } catch (err) {
    banner(
      $("#request-banner"),
      "error",
      `Could not parse the incoming <code>SAMLRequest</code>: ${escapeHtml(err.message)}`
    );
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// Build response from the form
// ---------------------------------------------------------------------------

function gatherUser() {
  const email = $("#email").value.trim();
  const first = $("#first-name").value.trim();
  const last = $("#last-name").value.trim();
  const roles = $("#roles").value.split(",").map((s) => s.trim()).filter(Boolean);

  const attributes = {};
  const set = (name, value) => {
    if (value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && !value.length)) {
      attributes[name] = value;
    }
  };
  set("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", email);
  set("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", first);
  set("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", last);
  set("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", [first, last].filter(Boolean).join(" "));
  set("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", $("#nameid").value.trim());
  if (roles.length) set("Role", roles);
  for (const { name, values } of readAttributeRows()) set(name, values.length > 1 ? values : values[0]);

  return {
    nameId: $("#nameid").value.trim(),
    nameIdFormat: $("#nameid-format").value,
    email,
    firstName: first,
    lastName: last,
    roles,
    attributes,
    acsUrl: $("#acs-url").value.trim(),
    audience: $("#audience").value.trim(),
    relayState: $("#relay-state").value.trim(),
    inResponseTo: $("#in-response-to").value.trim(),
  };
}

async function generate() {
  const user = gatherUser();
  if (!user.acsUrl) {
    toast("Set an ACS URL first");
    showTab("signin");
    $("#acs-url").focus();
    return null;
  }
  const requestConfig = {
    ...state.config,
    sessionTtlSeconds: Number($("#session-ttl").value) || state.config.sessionTtlSeconds,
  };
  const result = await S.buildSamlResponse({
    config: requestConfig,
    keyMaterial: state.keys,
    user,
    request: state.request,
  });
  state.lastResponse = result;
  renderResult(result);
  return result;
}

function renderResult(result) {
  const box = $("#result");
  box.hidden = false;
  $("#response-base64").value = result.base64;
  $("#response-xml").textContent = state.pretty ? S.prettyXml(result.xml) : result.xml;
  $("#result-summary").textContent =
    `sign ${state.config.signAssertion ? "assertion" : ""}${state.config.signAssertion && state.config.signResponse ? " + " : ""}${state.config.signResponse ? "response" : ""}`.trim() || "unsigned";
  $("#verify-result").hidden = true;
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

function doPost() {
  const result = state.lastResponse;
  if (!result) return;
  if (!result.acsUrl) {
    toast("No ACS URL");
    return;
  }
  const form = document.createElement("form");
  form.method = "POST";
  form.action = result.acsUrl;
  if (state.config.postTarget) form.target = state.config.postTarget;

  const add = (name, value) => {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  };
  add("SAMLResponse", result.base64);
  if (result.relayState) add("RelayState", result.relayState);

  document.body.appendChild(form);
  form.submit();
  form.remove();
}

async function verifyCurrent() {
  const box = $("#verify-result");
  if (!state.lastResponse) return;
  const xml = state.lastResponse.xml;
  try {
    const doc = xmldsig.Parse(xml);
    const sigs = [...doc.getElementsByTagNameNS(S.NS.ds, "Signature")];
    if (!sigs.length) {
      banner(box, "warn", "No <code>ds:Signature</code> found in the response.");
      return;
    }
    const lines = [];
    let allOk = true;
    for (let i = 0; i < sigs.length; i++) {
      const sx = new xmldsig.SignedXml(doc);
      sx.LoadXml(sigs[i]);
      let ok = false;
      let error = "";
      try {
        ok = await sx.Verify();
      } catch (err) {
        error = err && err.message ? err.message : String(err);
      }
      allOk = allOk && ok;
      lines.push(`Signature #${i + 1}: ${ok ? "✅ valid" : "❌ invalid"}${error ? ` — ${escapeHtml(error)}` : ""}`);
    }
    banner(box, allOk ? "ok" : "error", lines.join("<br />"));
  } catch (err) {
    banner(box, "error", `Verification error: ${escapeHtml(err.message)}`);
  }
}

// ---------------------------------------------------------------------------
// Metadata & certificate rendering
// ---------------------------------------------------------------------------

function renderMetadata() {
  if (!state.keys) return;
  $("#metadata-xml").textContent = S.buildMetadataXml({ config: state.config, keyMaterial: state.keys });
}

function renderCertificate() {
  if (!state.keys) return;
  const k = state.keys;
  $("#cert-pem").textContent = k.certificatePem;
  $("#pubkey-pem").textContent = spkiToPem(k.publicKeySpki);
  const kv = $("#cert-info");
  const rows = [
    ["Key source", state.keySource],
    ["Subject (CN)", k.commonName || "—"],
    ["Algorithm", k.algorithm || "—"],
    ["SHA-256 thumbprint", k.thumbprint || "—"],
    ["Valid from", k.notBefore ? new Date(k.notBefore).toUTCString() : "—"],
    ["Valid until", k.notAfter ? new Date(k.notAfter).toUTCString() : "—"],
  ];
  kv.innerHTML = rows.map(([dt, dd]) => `<dt>${escapeHtml(dt)}</dt><dd>${escapeHtml(dd)}</dd>`).join("");
}

// ---------------------------------------------------------------------------
// Configuration form
// ---------------------------------------------------------------------------

function fillConfigForm() {
  const c = state.config;
  $("#cfg-idp-entity").value = c.idpEntityId;
  $("#cfg-sso-url").value = c.ssoUrl;
  $("#cfg-acs-url").value = c.spAcsUrl;
  $("#cfg-sp-entity").value = c.spEntityId;
  $("#cfg-nameid-format").value = c.nameIdFormat;
  $("#cfg-authn-context").value = c.authnContextClassRef;
  $("#cfg-display-name").value = c.idpDisplayName;
  $("#cfg-assertion-ttl").value = c.assertionTtlSeconds;
  $("#cfg-session-ttl").value = c.sessionTtlSeconds;
  $("#cfg-post-target").value = c.postTarget;
  $("#cfg-sign-assertion").checked = !!c.signAssertion;
  $("#cfg-sign-response").checked = !!c.signResponse;
  $("#cfg-want-signed").checked = !!c.wantAuthnRequestsSigned;
  $("#session-ttl").value = c.sessionTtlSeconds;
}

function readConfigForm() {
  state.config = {
    ...state.config,
    idpEntityId: $("#cfg-idp-entity").value.trim(),
    ssoUrl: $("#cfg-sso-url").value.trim(),
    spAcsUrl: $("#cfg-acs-url").value.trim(),
    spEntityId: $("#cfg-sp-entity").value.trim(),
    nameIdFormat: $("#cfg-nameid-format").value,
    authnContextClassRef: $("#cfg-authn-context").value,
    idpDisplayName: $("#cfg-display-name").value.trim(),
    assertionTtlSeconds: Number($("#cfg-assertion-ttl").value) || 300,
    sessionTtlSeconds: Number($("#cfg-session-ttl").value) || 3600,
    postTarget: $("#cfg-post-target").value,
    signAssertion: $("#cfg-sign-assertion").checked,
    signResponse: $("#cfg-sign-response").checked,
    wantAuthnRequestsSigned: $("#cfg-want-signed").checked,
  };
  return state.config;
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function bindEvents() {
  for (const btn of $$(".tabs button")) {
    btn.addEventListener("click", () => {
      location.hash = btn.dataset.tab;
      showTab(btn.dataset.tab);
    });
  }
  window.addEventListener("hashchange", () => {
    const name = location.hash.replace(/^#\/?/, "") || "signin";
    showTab(name);
  });

  $("#add-attribute").addEventListener("click", () => addAttributeRow());

  $("#signin-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#submit-post");
    btn.disabled = true;
    try {
      const result = await generate();
      if (result) doPost();
    } catch (err) {
      toast(`Error: ${err.message}`);
      console.error(err);
    } finally {
      btn.disabled = false;
    }
  });

  $("#preview").addEventListener("click", async () => {
    try {
      await generate();
    } catch (err) {
      toast(`Error: ${err.message}`);
      console.error(err);
    }
  });

  $("#post-again").addEventListener("click", doPost);
  $("#verify-response").addEventListener("click", verifyCurrent);
  $("#toggle-pretty").addEventListener("click", () => {
    state.pretty = !state.pretty;
    if (state.lastResponse) {
      $("#response-xml").textContent = state.pretty ? S.prettyXml(state.lastResponse.xml) : state.lastResponse.xml;
    }
  });
  $("#download-response").addEventListener("click", () => {
    if (state.lastResponse) download("saml-response.xml", state.lastResponse.xml);
  });
  $("#download-base64").addEventListener("click", () => {
    if (state.lastResponse) download("saml-response.b64", state.lastResponse.base64, "text/plain");
  });
  $("#copy-base64").addEventListener("click", () => {
    if (state.lastResponse) copy(state.lastResponse.base64);
  });

  $("#config-form").addEventListener("submit", (e) => {
    e.preventDefault();
    readConfigForm();
    saveConfig(state.config);
    updateKeyStatus();
    renderMetadata();
    renderCertificate();
    toast("Configuration saved");
  });
  $("#reset-config").addEventListener("click", () => {
    state.config = defaultConfig();
    saveConfig(state.config);
    fillConfigForm();
    toast("Configuration reset");
  });

  $("#download-metadata").addEventListener("click", () => {
    if (state.keys) download("metadata.xml", S.buildMetadataXml({ config: state.config, keyMaterial: state.keys }));
  });
  $("#copy-metadata").addEventListener("click", () => {
    if (state.keys) copy(S.buildMetadataXml({ config: state.config, keyMaterial: state.keys }));
  });
  $("#refresh-metadata").addEventListener("click", renderMetadata);

  $("#download-cert").addEventListener("click", () => {
    if (state.keys) download("idp-cert.pem", state.keys.certificatePem, "application/x-pem-file");
  });
  $("#copy-cert").addEventListener("click", () => {
    if (state.keys) copy(state.keys.certificatePem);
  });
  $("#regen-keys").addEventListener("click", async () => {
    if (!confirm("Generate a new signing key pair? Any SP configured with the current certificate must be updated.")) return;
    try {
      await regenerateKeys();
    } catch (err) {
      setKeyStatus("key error", "error");
      toast(`Key generation failed: ${err.message}`);
    }
  });
  $("#use-demo-key").addEventListener("click", useDemoKey);
}

async function init() {
  fillSelect($("#nameid-format"), Object.entries(S.NAMEID_FORMATS).map(([k, v]) => [v, k]));
  fillSelect($("#cfg-nameid-format"), Object.entries(S.NAMEID_FORMATS).map(([k, v]) => [v, k]));
  fillSelect($("#cfg-authn-context"), Object.entries(S.AUTHN_CONTEXT).map(([k, v]) => [v, k]));

  if (!globalThis.crypto?.subtle || typeof DecompressionStream === "undefined") {
    banner(
      $("#warning"),
      "warn",
      "This browser lacks a required API (Web Crypto or DecompressionStream). Serve the page over <code>https://</code> or <code>http://localhost</code> and use a recent Chromium/Firefox/Safari."
    );
  }

  fillConfigForm();
  addAttributeRow("department", "Engineering");
  addAttributeRow("groups", "admins, users");

  try {
    await ensureKeys();
    updateKeyStatus();
  } catch (err) {
    setKeyStatus("key error", "error");
    banner($("#warning"), "error", `Key initialisation failed: ${escapeHtml(err.message)}`);
  }

  renderCertificate();
  renderMetadata();
  bindEvents();

  const initialTab = location.hash.replace(/^#\/?/, "") || "signin";
  showTab(initialTab);

  await handleIncomingRequest();
}

init();
