// Emits static SAML metadata (and the public certificate) from the bundled
// demo key so they can be served from a stable path on GitHub Pages.
//
// Usage:
//   SSO_URL=https://example.github.io/mock-saml/ \
//   IDP_ENTITY_ID=https://example.github.io/mock-saml/ \
//   node scripts/gen-static.mjs
import { readFileSync, writeFileSync } from "node:fs";
import * as S from "../saml.js";

const keyMaterial = JSON.parse(readFileSync("idp-key.json", "utf8"));

const ssoUrl = process.env.SSO_URL || "http://localhost:8080/";
const idpEntityId = process.env.IDP_ENTITY_ID || ssoUrl;

const config = {
  idpEntityId,
  ssoUrl,
  wantAuthnRequestsSigned: false,
  idpDisplayName: "Mock SAML IdP",
};

writeFileSync("metadata.xml", S.buildMetadataXml({ config, keyMaterial }) + "\n");
writeFileSync("idp-cert.pem", keyMaterial.certificatePem);
console.log(`Wrote metadata.xml (SSO=${ssoUrl}, entityID=${idpEntityId}) and idp-cert.pem`);
