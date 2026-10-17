// Generates the throwaway RSA key used by the *static* mock OIDC provider.
// The private key is committed on purpose (like the mock SAML IdP's demo key)
// — it is public and for local testing only. Writes:
//
//   oidc/key.json   { kid, privateJwk, publicJwk }
//   oidc/jwks.json  { keys: [publicJwk] }
//
// Usage: node scripts/gen-oidc-key.mjs
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

const privateJwk = privateKey.export({ format: "jwk" });
const publicJwk = publicKey.export({ format: "jwk" });

// RFC 7638 JWK thumbprint, used as the stable `kid`.
const kid = b64url(
  crypto
    .createHash("sha256")
    .update(JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n }))
    .digest()
);

const withMeta = (jwk) => ({ ...jwk, kid, use: "sig", alg: "RS256" });

writeFileSync(
  new URL("../oidc/key.json", import.meta.url),
  JSON.stringify({ kid, privateJwk: withMeta(privateJwk), publicJwk: withMeta(publicJwk) }, null, 2) + "\n"
);
writeFileSync(
  new URL("../oidc/jwks.json", import.meta.url),
  JSON.stringify({ keys: [withMeta(publicJwk)] }, null, 2) + "\n"
);

console.log(`Wrote oidc/key.json and oidc/jwks.json (kid=${kid})`);
