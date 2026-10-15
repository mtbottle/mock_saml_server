// Generates the bundled demo IdP key pair + self-signed certificate.
// The private key is intentionally public: this is a throwaway test key for a
// mock IdP and MUST NOT be used for anything real.
//
// Usage: node scripts/gen-idp-key.mjs
import "reflect-metadata";
import { writeFileSync } from "node:fs";
import * as x509 from "@peculiar/x509";

const crypto = globalThis.crypto;
if (!crypto?.subtle) throw new Error("Web Crypto unavailable in this Node version");

const alg = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
const now = new Date();
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Mock SAML IdP (demo)",
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

const b64 = (buf) => Buffer.from(buf).toString("base64");
const output = {
  privateKeyPkcs8: b64(await crypto.subtle.exportKey("pkcs8", keys.privateKey)),
  publicKeySpki: b64(await crypto.subtle.exportKey("spki", keys.publicKey)),
  certificatePem: cert.toString("pem"),
  certificateBase64: b64(cert.rawData),
  thumbprint: Buffer.from(await crypto.subtle.digest("SHA-256", cert.rawData)).toString("hex"),
  commonName: "Mock SAML IdP (demo)",
  notBefore: cert.notBefore.toISOString(),
  notAfter: cert.notAfter.toISOString(),
  createdAt: now.toISOString(),
  algorithm: "RSA 2048 / SHA-256 (RSASSA-PKCS1-v1_5)",
};

writeFileSync("idp-key.json", JSON.stringify(output, null, 2) + "\n");
writeFileSync("idp-cert.pem", cert.toString("pem"));
console.log("Wrote idp-key.json and idp-cert.pem");
