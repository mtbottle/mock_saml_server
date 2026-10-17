# Mock OIDC Provider

A **fully static, client-side** mock OpenID Connect provider for integration
testing. It signs an `id_token` in your browser with a bundled throwaway key
and serves everything as static files, so it hosts on **GitHub Pages**.

> ⚠️ **Not for production.** The bundled private key (`key.json`) is public.

The issuer is `https://michtran.ca/mock_saml_server/oidc` (see `config.json`).

## Endpoints

All paths are under the issuer base (`…/oidc/`).

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | Discovery document. |
| `GET` | `/openid-configuration.json` | Same document with an explicit JSON filename. |
| `GET` | `/jwks.json` | JSON Web Key Set (RS256 public key). |
| `GET` | `/authorize` | Authorization endpoint (implicit). |
| `GET` | `/` | Landing page / in-browser token generator. |

## Spec support

### Implemented

- **Discovery** and **JWKS**.
- **OAuth 2.0 implicit flow only** — `response_type=id_token` and
  `id_token token`.
- **`response_mode`** — `fragment` (default), `query`, `form_post`.
- **Scopes** — `openid` (required), `profile`, `email`, `groups`.
- **`id_token` claims** — `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`,
  `nonce`; `profile` → `name`, `given_name`, `family_name`,
  `preferred_username`, `groups`; `email` → `email`, `email_verified`.
- **`access_token`** — JWT when `token` is requested; `token_type=Bearer`,
  `expires_in`.
- **Signing** — RS256 (RSASSA-PKCS1-v1_5 / SHA-256); the public key is
  published at `jwks.json`, so the `id_token` verifies against discovery.
- **Validation** — requires the `openid` scope; rejects `response_type=code`;
  echoes `state`; passes through `nonce`.

### Not implemented (needs a server / back channel)

- **Authorization-code flow** — no `token_endpoint`, so no code exchange and no
  PKCE. A static host cannot accept the server-to-server token request, which
  is why this provider is implicit-only.
- Refresh tokens, UserInfo endpoint, token introspection, token revocation.
- Request objects (`request` / `request_uri`), dynamic client registration.
- Encrypted tokens (JWE) — the `id_token` is signed (JWS) only.
