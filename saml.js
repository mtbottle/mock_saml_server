// Core SAML 2.0 construction, signing and metadata generation.
// Pure-ish module: only relies on standard web platform globals
// (crypto, TextEncoder/Decoder, DOMParser, DecompressionStream, Blob, Response).
import { xmldsig, x509 } from "./vendor.js";

export const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  xs: "http://www.w3.org/2001/XMLSchema",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
};

export const BINDING = {
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
};

export const NAMEID_FORMATS = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  emailAddress: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
  entity: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
  kerberos: "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
  windowsDomainQualifiedName:
    "urn:oasis:names:tc:SAML:2.0:nameid-format:WindowsDomainQualifiedName",
};

export const AUTHN_CONTEXT = {
  pwdProtectedTransport:
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  password: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
  unspecified: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
  x509: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
  kerberos: "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
};

// ---------------------------------------------------------------------------
// Low level helpers
// ---------------------------------------------------------------------------

export function randomId(prefix = "_") {
  return prefix + crypto.randomUUID().replace(/-/g, "");
}

export function samlInstant(date = new Date()) {
  return new Date(date).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function escapeXml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    binary += String.fromCharCode.apply(null, arr.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const normalized = base64UrlToBase64(String(b64).replace(/\s+/g, ""));
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64UrlToBase64(input) {
  const s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  return s + "=".repeat((4 - (s.length % 4)) % 4);
}

export function base64ToBase64Url(input) {
  return String(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function encodeSamlMessage(xml) {
  return bytesToBase64(utf8Bytes(xml));
}

export function b64encodeUtf8(str) {
  return bytesToBase64(utf8Bytes(str));
}

export function b64decodeUtf8(b64) {
  return new TextDecoder().decode(base64ToBytes(b64));
}

export function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Naive pretty printer for *display only*. Never feed its output back into a signature. */
export function prettyXml(xml, indent = "  ") {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) return xml;
  const format = (node, depth) => {
    const pad = indent.repeat(depth);
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent.trim();
      return text ? pad + text + "\n" : "";
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return "";
    const open = `<${node.nodeName}` +
      [...node.attributes]
        .map((a) => ` ${a.name}="${a.value.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}"`)
        .join("") + ">";
    const children = [...node.childNodes].map((c) => format(c, depth + 1)).join("");
    if (!children.trim()) return pad + open + `</${node.nodeName}>\n`;
    return pad + open + "\n" + children + pad + `</${node.nodeName}>\n`;
  };
  return format(doc.documentElement, 0).trimEnd();
}

// ---------------------------------------------------------------------------
// Key / certificate material
// ---------------------------------------------------------------------------

function randomSerialHex() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0] &= 0x7f; // positive integer
  return arrayBufferToHex(bytes.buffer).replace(/^0+/, "") || "1";
}

export async function generateKeyMaterial(commonName = "Mock SAML IdP") {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "Web Crypto is unavailable. Serve the page over https:// or http://localhost."
    );
  }
  const alg = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
  };
  const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: `CN=${commonName}`,
    notBefore: new Date(now.getTime() - 24 * 60 * 60 * 1000),
    notAfter: new Date(now.getTime() + 3650 * 24 * 60 * 60 * 1000),
    signingAlgorithm: alg,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
  const thumbprint = await crypto.subtle.digest("SHA-256", cert.rawData);

  return {
    privateKeyPkcs8: bytesToBase64(new Uint8Array(pkcs8)),
    publicKeySpki: bytesToBase64(new Uint8Array(spki)),
    certificatePem: cert.toString("pem"),
    certificateBase64: bytesToBase64(new Uint8Array(cert.rawData)),
    thumbprint: arrayBufferToHex(thumbprint),
    commonName,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    createdAt: now.toISOString(),
    algorithm: "RSA 2048 / SHA-256 (RSASSA-PKCS1-v1_5)",
  };
}

export async function importSigningKey(pkcs8Base64) {
  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBytes(pkcs8Base64),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// ---------------------------------------------------------------------------
// XML builders (compact: no insignificant whitespace, so the digest is stable)
// ---------------------------------------------------------------------------

function buildAttributeXml(attr) {
  const values = Array.isArray(attr.values) ? attr.values : [attr.values];
  const nameFormat =
    attr.nameFormat || "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
  let xml = `<saml:Attribute Name="${escapeXml(attr.name)}" NameFormat="${escapeXml(
    nameFormat
  )}"`;
  if (attr.friendlyName) xml += ` FriendlyName="${escapeXml(attr.friendlyName)}"`;
  xml += ">";
  for (const v of values) {
    if (v === undefined || v === null || v === "") continue;
    xml += `<saml:AttributeValue xsi:type="xs:string">${escapeXml(v)}</saml:AttributeValue>`;
  }
  xml += "</saml:Attribute>";
  return xml;
}

export function buildAssertionXml(o) {
  const cond = o.conditions || {};
  const scd = o.subjectConfirmationData || {};
  let xml =
    `<saml:Assertion xmlns:saml="${NS.saml}" xmlns:xs="${NS.xs}" xmlns:xsi="${NS.xsi}"` +
    ` Version="2.0" ID="${escapeXml(o.assertionId)}" IssueInstant="${escapeXml(o.issueInstant)}">`;
  xml += `<saml:Issuer>${escapeXml(o.issuer)}</saml:Issuer>`;

  if (o.nameId) {
    xml += `<saml:Subject><saml:NameID`;
    if (o.nameIdFormat) xml += ` Format="${escapeXml(o.nameIdFormat)}"`;
    if (o.nameIdSPNameQualifier)
      xml += ` SPNameQualifier="${escapeXml(o.nameIdSPNameQualifier)}"`;
    xml += `>${escapeXml(o.nameId)}</saml:NameID>`;
    xml += `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`;
    xml += `<saml:SubjectConfirmationData`;
    if (scd.inResponseTo)
      xml += ` InResponseTo="${escapeXml(scd.inResponseTo)}"`;
    if (scd.notOnOrAfter)
      xml += ` NotOnOrAfter="${escapeXml(scd.notOnOrAfter)}"`;
    if (scd.recipient) xml += ` Recipient="${escapeXml(scd.recipient)}"`;
    if (scd.notBefore) xml += ` NotBefore="${escapeXml(scd.notBefore)}"`;
    if (scd.address) xml += ` Address="${escapeXml(scd.address)}"`;
    xml += `/></saml:SubjectConfirmation></saml:Subject>`;
  }

  if (cond.notBefore || cond.notOnOrAfter || o.audience) {
    xml += "<saml:Conditions";
    if (cond.notBefore) xml += ` NotBefore="${escapeXml(cond.notBefore)}"`;
    if (cond.notOnOrAfter)
      xml += ` NotOnOrAfter="${escapeXml(cond.notOnOrAfter)}"`;
    xml += ">";
    if (o.audience) {
      xml += `<saml:AudienceRestriction><saml:Audience>${escapeXml(
        o.audience
      )}</saml:Audience></saml:AudienceRestriction>`;
    }
    xml += "</saml:Conditions>";
  }

  if (o.authnStatement !== false) {
    xml += `<saml:AuthnStatement AuthnInstant="${escapeXml(
      o.authnInstant || o.issueInstant
    )}"`;
    if (o.sessionIndex) xml += ` SessionIndex="${escapeXml(o.sessionIndex)}"`;
    if (o.sessionNotOnOrAfter)
      xml += ` SessionNotOnOrAfter="${escapeXml(o.sessionNotOnOrAfter)}"`;
    xml += ">";
    xml += `<saml:AuthnContext><saml:AuthnContextClassRef>${escapeXml(
      o.authnContextClassRef || AUTHN_CONTEXT.pwdProtectedTransport
    )}</saml:AuthnContextClassRef></saml:AuthnContext>`;
    xml += "</saml:AuthnStatement>";
  }

  const attrs = (o.attributes || []).filter((a) => a && a.name);
  if (attrs.length) {
    xml += "<saml:AttributeStatement>";
    for (const a of attrs) xml += buildAttributeXml(a);
    xml += "</saml:AttributeStatement>";
  }

  xml += "</saml:Assertion>";
  return xml;
}

export function buildResponseXml(o) {
  let xml =
    `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}"` +
    ` xmlns:xs="${NS.xs}" xmlns:xsi="${NS.xsi}" Version="2.0"` +
    ` ID="${escapeXml(o.responseId)}" IssueInstant="${escapeXml(o.issueInstant)}"`;
  if (o.destination) xml += ` Destination="${escapeXml(o.destination)}"`;
  if (o.inResponseTo) xml += ` InResponseTo="${escapeXml(o.inResponseTo)}"`;
  xml += ">";
  xml += `<saml:Issuer>${escapeXml(o.issuer)}</saml:Issuer>`;
  xml += `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`;
  if (o.assertionXml) xml += o.assertionXml;
  xml += "</samlp:Response>";
  return xml;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

// SAML's schema requires any enveloped ds:Signature to sit directly after the
// saml:Issuer (before Subject/Status/etc). xmldsigjs appends the signature as
// the last child instead, which fails XSD validation, so move it into place
// once signing is done. Moving it does not affect the digest: the enveloped
// transform removes the signature subtree before hashing, and the SignedInfo
// canonicalization is position-independent.
function placeSignatureAfterIssuer(el) {
  const sigs = el.getElementsByTagNameNS(NS.ds, "Signature");
  let sig = null;
  for (let i = 0; i < sigs.length; i++) {
    if (sigs[i].parentNode === el) {
      sig = sigs[i];
      break;
    }
  }
  if (!sig) return el;

  const issuers = el.getElementsByTagNameNS(NS.saml, "Issuer");
  let issuer = null;
  for (let i = 0; i < issuers.length; i++) {
    if (issuers[i].parentNode === el) {
      issuer = issuers[i];
      break;
    }
  }

  const anchor = issuer ? issuer.nextSibling : el.firstChild;
  if (anchor !== sig) el.insertBefore(sig, anchor);
  return el;
}

async function signNode(node, signingKey, x509Base64, uri) {
  const signedXml = new xmldsig.SignedXml(node);
  // Use exclusive canonicalization for SignedInfo so the signature does not
  // depend on namespaces inherited from an ancestor (e.g. samlp on the
  // Response when signing a nested Assertion).
  signedXml.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = EXC_C14N;
  await signedXml.Sign(
    { name: "RSASSA-PKCS1-v1_5" },
    signingKey,
    node,
    {
      references: [
        { uri, hash: "SHA-256", transforms: ["enveloped", "exc-c14n"] },
      ],
      x509: x509Base64 ? [x509Base64] : undefined,
    }
  );
  const signed = signedXml.toString();
  const doc = new DOMParser().parseFromString(signed, "application/xml");
  placeSignatureAfterIssuer(doc.documentElement);
  return new XMLSerializer().serializeToString(doc);
}

export async function signXml(xml, signingKey, x509Base64, uri) {
  const doc = xmldsig.Parse(xml);
  return signNode(doc.documentElement, signingKey, x509Base64, uri);
}

// ---------------------------------------------------------------------------
// Full response assembly
// ---------------------------------------------------------------------------

/**
 * Build (and optionally sign) a SAML Response.
 * @param {object} params
 * @param {object} params.config  IdP configuration (see app defaults)
 * @param {object} params.keyMaterial generated key material
 * @param {object} params.user    subject + attributes
 * @param {object} [params.request] parsed AuthnRequest (SP initiated) or null
 */
export async function buildSamlResponse({ config, keyMaterial, user, request }) {
  const now = new Date();
  const issueInstant = samlInstant(now);
  const responseId = randomId("_");
  const assertionId = randomId("_");
  const sessionIndex = randomId("_");

  const assertionTtl = Number(config.assertionTtlSeconds ?? 300) * 1000;
  const sessionTtl = Number(config.sessionTtlSeconds ?? 3600) * 1000;

  const acsUrl = user.acsUrl || config.spAcsUrl || "";
  const audience = user.audience || config.spEntityId || "";
  const inResponseTo = (request && request.id) || user.inResponseTo || "";
  const nameIdFormat =
    user.nameIdFormat || (request && request.nameIdFormat) || config.nameIdFormat;

  const attributes = [];
  for (const [name, value] of Object.entries(user.attributes || {})) {
    if (value === undefined || value === null || value === "") continue;
    attributes.push({ name, values: Array.isArray(value) ? value : [value] });
  }

  const assertionXml = buildAssertionXml({
    assertionId,
    issuer: config.idpEntityId,
    issueInstant,
    nameId: user.nameId,
    nameIdFormat,
    nameIdSPNameQualifier: audience,
    subjectConfirmationData: {
      inResponseTo,
      notOnOrAfter: samlInstant(now.getTime() + assertionTtl),
      recipient: acsUrl,
      address: user.clientAddress,
    },
    conditions: {
      notBefore: samlInstant(now.getTime() - 5000),
      notOnOrAfter: samlInstant(now.getTime() + assertionTtl),
    },
    audience,
    authnInstant: issueInstant,
    sessionIndex,
    sessionNotOnOrAfter: samlInstant(now.getTime() + sessionTtl),
    authnContextClassRef: config.authnContextClassRef,
    attributes,
  });

  let signingKey = null;
  if (config.signAssertion || config.signResponse) {
    signingKey = await importSigningKey(keyMaterial.privateKeyPkcs8);
  }

  let signedAssertionXml = assertionXml;
  if (config.signAssertion) {
    signedAssertionXml = await signXml(
      assertionXml,
      signingKey,
      keyMaterial.certificateBase64,
      `#${assertionId}`
    );
  }

  let responseXml = buildResponseXml({
    responseId,
    issueInstant,
    destination: acsUrl,
    inResponseTo,
    issuer: config.idpEntityId,
    assertionXml: signedAssertionXml,
  });

  if (config.signResponse) {
    responseXml = await signXml(
      responseXml,
      signingKey,
      keyMaterial.certificateBase64,
      ""
    );
  }

  return {
    xml: responseXml,
    base64: encodeSamlMessage(responseXml),
    responseId,
    assertionId,
    sessionIndex,
    issueInstant,
    inResponseTo,
    acsUrl,
    audience,
    relayState: user.relayState || "",
  };
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

export function buildMetadataXml({ config, keyMaterial }) {
  const cert = keyMaterial.certificateBase64;
  let xml = `<?xml version="1.0" encoding="UTF-8"?>`;
  xml += `<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}"`;
  xml += ` entityID="${escapeXml(config.idpEntityId)}" validUntil="${escapeXml(
    samlInstant(new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000))
  )}">`;
  xml += `<md:IDPSSODescriptor protocolSupportEnumeration="${NS.samlp}"`;
  xml += ` WantAuthnRequestsSigned="${config.wantAuthnRequestsSigned ? "true" : "false"}">`;
  xml += `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>`;
  xml += `<ds:X509Certificate>${cert}</ds:X509Certificate>`;
  xml += `</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;
  for (const f of Object.values(NAMEID_FORMATS)) {
    xml += `<md:NameIDFormat>${f}</md:NameIDFormat>`;
  }
  xml += `<md:SingleSignOnService Binding="${BINDING.redirect}" Location="${escapeXml(
    config.ssoUrl
  )}"/>`;
  xml += `<md:SingleSignOnService Binding="${BINDING.post}" Location="${escapeXml(
    config.ssoUrl
  )}"/>`;
  xml += `</md:IDPSSODescriptor>`;
  if (config.idpDisplayName) {
    xml += `<md:Organization><md:OrganizationName xml:lang="en">${escapeXml(
      config.idpDisplayName
    )}</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">${escapeXml(
      config.idpDisplayName
    )}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">${escapeXml(
      config.ssoUrl
    )}</md:OrganizationURL></md:Organization>`;
  }
  xml += `</md:EntityDescriptor>`;
  return xml;
}

// ---------------------------------------------------------------------------
// AuthnRequest parsing (SP initiated flow)
// ---------------------------------------------------------------------------

export function parseAuthnRequest(xmlString) {
  const doc = new DOMParser().parseFromString(xmlString, "application/xml");
  const error = doc.getElementsByTagName("parsererror");
  if (error.length) throw new Error("Invalid AuthnRequest XML");
  const root = doc.documentElement;
  const issuerEl = doc.getElementsByTagNameNS(NS.saml, "Issuer")[0];
  const nameIdPolicy = doc.getElementsByTagNameNS(NS.samlp, "NameIDPolicy")[0];
  const requestedAuthnContext = doc.getElementsByTagNameNS(
    NS.samlp,
    "RequestedAuthnContext"
  )[0];
  return {
    id: root.getAttribute("ID") || "",
    acsUrl: root.getAttribute("AssertionConsumerServiceURL") || "",
    destination: root.getAttribute("Destination") || "",
    protocolBinding: root.getAttribute("ProtocolBinding") || BINDING.post,
    issueInstant: root.getAttribute("IssueInstant") || "",
    spEntityId: issuerEl ? issuerEl.textContent.trim() : "",
    nameIdFormat: nameIdPolicy ? nameIdPolicy.getAttribute("Format") || "" : "",
    forceAuthn: root.getAttribute("ForceAuthn") === "true",
    isPassive: root.getAttribute("IsPassive") === "true",
    authnContextComparison:
      requestedAuthnContext?.getAttribute("Comparison") || "",
    raw: xmlString,
  };
}

async function inflateRaw(bytes) {
  const attempts = ["deflate-raw", "deflate"];
  let lastError;
  for (const format of attempts) {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(
        new DecompressionStream(format)
      );
      const buffer = await new Response(stream).arrayBuffer();
      return new TextDecoder().decode(buffer);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Unable to inflate SAML message");
}

export async function decodeSamlMessage(encoded) {
  const bytes = base64ToBytes(encoded);
  // Try as a plain (uncompressed) base64 XML first, then as raw deflate.
  const asText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const trimmed = asText.trimStart();
  if (trimmed.startsWith("<")) return asText;
  return inflateRaw(bytes);
}

export async function parseSamlRequestParam(encoded) {
  const xml = await decodeSamlMessage(encoded);
  return parseAuthnRequest(xml);
}
