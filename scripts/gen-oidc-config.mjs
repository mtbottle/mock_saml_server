// Emits the static OIDC discovery document from oidc/config.json so it can be
// served from a stable path on GitHub Pages. Writes both the canonical
// `/.well-known/openid-configuration` and an explicit `.json` copy (GitHub
// Pages does not always set a JSON content-type on extensionless files).
//
// Usage:
//   node scripts/gen-oidc-config.mjs
//   ISSUER=https://example.github.io/mock/oidc node scripts/gen-oidc-config.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const configUrl = new URL("../oidc/config.json", import.meta.url);
const config = JSON.parse(readFileSync(configUrl, "utf8"));
const issuer = (process.env.ISSUER || config.issuer).replace(/\/$/, "");

const discovery = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  jwks_uri: `${issuer}/jwks.json`,
  response_types_supported: ["id_token", "id_token token"],
  response_modes_supported: ["fragment", "query", "form_post"],
  grant_types_supported: ["implicit"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email", "groups"],
  claims_supported: [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "groups",
  ],
  token_endpoint_auth_methods_supported: [],
  claims_parameter_supported: false,
  request_parameter_supported: false,
  request_uri_parameter_supported: false,
};

const json = JSON.stringify(discovery, null, 2) + "\n";

writeFileSync(new URL("../oidc/openid-configuration.json", import.meta.url), json);
mkdirSync(new URL("../oidc/.well-known/", import.meta.url), { recursive: true });
const wellKnown = new URL("../oidc/.well-known/openid-configuration", import.meta.url);
writeFileSync(wellKnown, json);

console.log(`Wrote oidc/.well-known/openid-configuration and oidc/openid-configuration.json (issuer=${issuer})`);
