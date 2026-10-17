// Verifies the static mock OIDC provider without a browser: builds an id_token
// with the bundled key (same code the authorize page uses) and checks it
// against the published jwks.json, plus a few consistency checks on the
// discovery document.
//
// Usage: node oidc/test.mjs  (or: npm run oidc:test)
import { readFile } from "node:fs/promises";
import {
  importPrivateJwk, signJwt, verifyJwt, unb64url,
  buildIdTokenPayload, buildAccessTokenPayload, normalizeScope, claimsForScope, DEFAULT_USER,
} from "./oidc.js";

const read = async (name) => JSON.parse(await readFile(new URL(name, import.meta.url), "utf8"));

const config = await read("./config.json");
const key = await read("./key.json");
const jwks = await read("./jwks.json");
const discovery = await read("./.well-known/openid-configuration");

let failures = 0;
function check(name, cond, detail = "") {
  const status = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`  [${status}] ${name}${detail ? " — " + detail : ""}`);
}

console.log("Static mock OIDC provider — verification harness\n");

console.log("== discovery ==");
check("issuer matches config", discovery.issuer === config.issuer);
check("authorization_endpoint", discovery.authorization_endpoint === `${config.issuer}/authorize`);
check("jwks_uri points at jwks.json", discovery.jwks_uri === `${config.issuer}/jwks.json`);
check("advertises implicit only", discovery.grant_types_supported.length === 1 && discovery.grant_types_supported[0] === "implicit");
check("no token_endpoint advertised", discovery.token_endpoint === undefined);
check("RS256 signing", discovery.id_token_signing_alg_values_supported.includes("RS256"));

console.log("\n== jwks ==");
check("jwks has one key", jwks.keys.length === 1);
check("jwks kid matches key.json", jwks.keys[0].kid === key.kid);
check("public key is RSA/sig/RS256", jwks.keys[0].kty === "RSA" && jwks.keys[0].use === "sig" && jwks.keys[0].alg === "RS256");
check("jwks has no private material", jwks.keys[0].d === undefined && jwks.keys[0].p === undefined);

console.log("\n== id_token ==");
const privateKey = await importPrivateJwk(key.privateJwk);
const scope = normalizeScope("openid profile email");
const payload = buildIdTokenPayload({
  issuer: config.issuer,
  clientId: "mock-client",
  user: DEFAULT_USER,
  scope,
  nonce: "nonce-abc",
  ttlSeconds: 3600,
});
const idToken = await signJwt(payload, privateKey, key.kid);

check("token has three parts", idToken.split(".").length === 3);
const header = JSON.parse(unb64url(idToken.split(".")[0]));
check("header alg/kid", header.alg === "RS256" && header.kid === key.kid);
check("header typ", header.typ === "JWT");

const verified = await verifyJwt(idToken, jwks.keys[0]);
check("signature verifies against jwks", !!verified);
check("iss matches discovery", verified.iss === config.issuer);
check("aud is client_id", verified.aud === "mock-client");
check("nonce echoed", verified.nonce === "nonce-abc");
check("sub present", verified.sub === DEFAULT_USER.sub);
check("email claim (email scope)", verified.email === DEFAULT_USER.email);
check("name claim (profile scope)", verified.name === DEFAULT_USER.name);
check("groups claim (profile scope)", Array.isArray(verified.groups));
check("exp is in the future", verified.exp > Math.floor(Date.now() / 1000));

console.log("\n== tamper detection ==");
const tampered = idToken.slice(0, -3) + (idToken.slice(-3) === "AAA" ? "BBB" : "AAA");
let threw = false;
try {
  await verifyJwt(tampered, jwks.keys[0]);
} catch {
  threw = true;
}
check("modified signature is rejected", threw);

console.log("\n== scope handling ==");
check("openid only → no email", claimsForScope(DEFAULT_USER, normalizeScope("openid")).email === undefined);
check("email scope → email", claimsForScope(DEFAULT_USER, normalizeScope("email")).email === DEFAULT_USER.email);

console.log("\n== access_token ==");
const at = await signJwt(
  buildAccessTokenPayload({ issuer: config.issuer, clientId: "mock-client", user: DEFAULT_USER, scope, ttlSeconds: 3600 }),
  privateKey,
  key.kid
);
const atClaims = await verifyJwt(at, jwks.keys[0]);
check("access_token verifies", !!atClaims);
check("access_token scope", atClaims.scope === scope.join(" "));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED ✅" : `${failures} CHECK(S) FAILED ❌`}`);
process.exit(failures === 0 ? 0 : 1);
