// Node harness: runs the *same* saml.js module used by the browser, then
// verifies the produced signatures with xmldsigjs AND independently with
// xml-crypto (a different implementation) to catch canonicalization bugs.
//
// Usage: node test/verify-node.mjs
import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { DOMParser, XMLSerializer, DOMImplementation } from "@xmldom/xmldom";

globalThis.DOMParser = DOMParser;
globalThis.XMLSerializer = XMLSerializer;
globalThis.DOMImplementation = DOMImplementation;
globalThis.Node = globalThis.Node || { ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, DOCUMENT_NODE: 9 };

const { xmldsig } = await import("../vendor.js");
xmldsig.Application.setEngine("node-webcrypto", globalThis.crypto);

const S = await import("../saml.js");
const { SignedXml } = await import("xml-crypto");

const keyMaterial = JSON.parse(await readFile(new URL("../idp-key.json", import.meta.url), "utf8"));

let failures = 0;
function check(name, cond, detail = "") {
  const status = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`  [${status}] ${name}${detail ? " — " + detail : ""}`);
}

function independentVerify(xml, certPem) {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const sigs = doc.getElementsByTagNameNS(S.NS.ds, "Signature");
  const results = [];
  for (let i = 0; i < sigs.length; i++) {
    const sig = new SignedXml({ publicCert: certPem, getCertFromKeyInfo: () => null });
    sig.loadSignature(sigs[i]);
    try {
      results.push(sig.checkSignature(xml));
    } catch (err) {
      results.push(`error: ${err.message}`);
    }
  }
  return results;
}

async function selfVerify(xml) {
  const doc = xmldsig.Parse(xml);
  const sigs = [...doc.getElementsByTagNameNS(S.NS.ds, "Signature")];
  const results = [];
  for (const node of sigs) {
    const sx = new xmldsig.SignedXml(doc);
    sx.LoadXml(node);
    try {
      results.push(await sx.Verify());
    } catch (err) {
      results.push(`error: ${err.message}`);
    }
  }
  return results;
}

const config = {
  idpEntityId: "https://idp.example.com/entityid",
  ssoUrl: "https://idp.example.com/sso",
  spAcsUrl: "https://sp.example.com/saml/acs",
  spEntityId: "https://sp.example.com/saml/metadata",
  nameIdFormat: S.NAMEID_FORMATS.persistent,
  authnContextClassRef: S.AUTHN_CONTEXT.pwdProtectedTransport,
  signAssertion: true,
  signResponse: false,
  assertionTtlSeconds: 300,
  sessionTtlSeconds: 3600,
};

const user = {
  nameId: "user@example.com",
  nameIdFormat: S.NAMEID_FORMATS.emailAddress,
  acsUrl: config.spAcsUrl,
  audience: config.spEntityId,
  attributes: {
    email: "user@example.com",
    firstName: "Ada",
    groups: ["admins", "users"],
  },
};

async function scenario(label, overrides, expectSigs) {
  console.log(`\n== ${label} ==`);
  const result = await S.buildSamlResponse({
    config: { ...config, ...overrides },
    keyMaterial,
    user,
    request: null,
  });
  const sigCount = (result.xml.match(/<ds:Signature[\s>]/g) || []).length;
  check(`produces ${expectSigs} signature(s)`, sigCount === expectSigs, `got ${sigCount}`);
  check("base64 round-trips", S.b64decodeUtf8(result.base64) === result.xml);

  if (overrides.signResponse) {
    // SAML requires an enveloped ds:Signature right after saml:Issuer and
    // before samlp:Status. xmldsigjs appends it last, so guard the fix.
    const sigIdx = result.xml.indexOf("<ds:Signature");
    const statusIdx = result.xml.indexOf("<samlp:Status");
    check(
      "response signature sits between Issuer and Status",
      sigIdx > -1 && sigIdx < statusIdx,
      `sig=${sigIdx} status=${statusIdx}`
    );
  }
  if (overrides.signAssertion) {
    // Inside the Assertion the signature must be after Issuer, before Subject.
    const aXml = result.xml.slice(result.xml.indexOf("<saml:Assertion"));
    const iIssuer = aXml.indexOf("<saml:Issuer>");
    const iSig = aXml.indexOf("<ds:Signature");
    const iSubject = aXml.indexOf("<saml:Subject>");
    check(
      "assertion signature sits between Issuer and Subject",
      iSig > iIssuer && iSig < iSubject,
      `issuer=${iIssuer} sig=${iSig} subject=${iSubject}`
    );
  }

  const self = await selfVerify(result.xml);
  check("xmldsigjs self-verifies", self.length === expectSigs && self.every((r) => r === true), JSON.stringify(self));

  const indep = independentVerify(result.xml, keyMaterial.certificatePem);
  check("xml-crypto independently verifies", indep.length === expectSigs && indep.every((r) => r === true), JSON.stringify(indep));

  return result;
}

console.log("Mock SAML IdP verification harness");

const assertionOnly = await scenario("assertion signed", { signAssertion: true, signResponse: false }, 1);
await scenario("response signed", { signAssertion: false, signResponse: true }, 1);
await scenario("both signed", { signAssertion: true, signResponse: true }, 2);
await scenario("unsigned", { signAssertion: false, signResponse: false }, 0);

console.log("\n== metadata ==");
const metadata = S.buildMetadataXml({ config, keyMaterial });
check("metadata includes entityID", metadata.includes(config.idpEntityId));
check("metadata includes SSO locations", metadata.includes('Location="https://idp.example.com/sso"'));
check("metadata includes certificate", metadata.includes(keyMaterial.certificateBase64));
check("metadata well-formed", !new DOMParser().parseFromString(metadata, "text/xml").getElementsByTagName("parsererror").length);

console.log("\n== AuthnRequest parsing ==");
const authnRequest =
  `<samlp:AuthnRequest xmlns:samlp="${S.NS.samlp}" xmlns:saml="${S.NS.saml}" ID="_abc123" Version="2.0" ` +
  `IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ` +
  `Destination="https://idp.example.com/sso"><saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>` +
  `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"/></samlp:AuthnRequest>`;
const parsed = S.parseAuthnRequest(authnRequest);
check("parses ACS URL", parsed.acsUrl === "https://sp.example.com/saml/acs");
check("parses issuer", parsed.spEntityId === "https://sp.example.com/saml/metadata");
check("parses InResponseTo id", parsed.id === "_abc123");
check("parses NameID format", parsed.nameIdFormat.endsWith("emailAddress"));

console.log("\n== AuthnRequest decode (base64, uncompressed) ==");
const encoded = S.encodeSamlMessage(authnRequest);
const decoded = await S.decodeSamlMessage(encoded);
check("decodes plain base64 SAMLRequest", decoded === authnRequest);

console.log("\n== AuthnRequest decode (raw deflate) ==");
const deflated = await new Response(
  new Blob([new TextEncoder().encode(authnRequest)]).stream().pipeThrough(new CompressionStream("deflate-raw"))
).arrayBuffer();
const deflatedB64 = S.bytesToBase64(new Uint8Array(deflated));
const decoded2 = await S.decodeSamlMessage(deflatedB64);
check("decodes deflated SAMLRequest", decoded2 === authnRequest);

console.log("\n== assertion content ==");
check("contains audience", assertionOnly.xml.includes(`<saml:Audience>${config.spEntityId}</saml:Audience>`));
check("contains NameID", assertionOnly.xml.includes(">user@example.com</saml:NameID>"));
check("contains group attribute values", assertionOnly.xml.includes(">admins</saml:AttributeValue>") && assertionOnly.xml.includes(">users</saml:AttributeValue>"));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED ✅" : `${failures} CHECK(S) FAILED ❌`}`);
process.exit(failures === 0 ? 0 : 1);
