# Mock SAML IdP & OIDC Provider

Two **fully client-side, static** mock identity providers for integration
testing — a **SAML 2.0 IdP** and an **OpenID Connect provider**. They run
entirely in the browser (no backend), so they can be hosted on GitHub Pages or
any static host.

> ⚠️ **Not for production.** The bundled demo keys are public and are only meant
> for integration testing.

This deployment's base URL is `https://michtran.ca/mock_saml_server/`
(`*.github.io` 301-redirects here).

## SAML 2.0 endpoints

All paths are relative to the base URL.

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/` | IdP login screen; builds and POSTs the signed response. Also accepts an inbound `?SAMLRequest=` in the browser. |
| `GET` | `/sso?SAMLRequest=…&RelayState=…` | The **SSO endpoint** advertised in metadata. A tiny static page that forwards to the app, preserving the query string (GitHub Pages can't run server routes). |
| `GET` | `/metadata.xml` | IdP metadata (`md:EntityDescriptor`). |
| `GET` | `/idp-cert.pem` | The X.509 signing certificate (PEM). |
| `POST` (external) | SP **ACS URL** | Outbound. The browser POSTs the `SAMLResponse` here (HTTP-POST binding). |

## OpenID Connect endpoints

All paths are under `/oidc/`.

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/oidc/.well-known/openid-configuration` | Discovery document. |
| `GET` | `/oidc/openid-configuration.json` | Same document, served with an explicit JSON filename. |
| `GET` | `/oidc/jwks.json` | JSON Web Key Set (RS256 public key). |
| `GET` | `/oidc/authorize` | Authorization endpoint (implicit). |
| `GET` | `/oidc/` | Landing page / in-browser token generator. |

## SAML 2.0 spec support

### Implemented

- **Bindings** — HTTP-Redirect (consuming the `AuthnRequest`, deflate + base64)
  and HTTP-POST (producing the `Response`).
- **Profiles** — Web Browser SSO, both **SP-initiated** and **IdP-initiated**.
- **`AuthnRequest` (parsed)** — `ID`, `AssertionConsumerServiceURL`,
  `Destination`, `ProtocolBinding`, `IssueInstant`, `Issuer`,
  `NameIDPolicy/@Format`, `ForceAuthn`, `IsPassive`,
  `RequestedAuthnContext/@Comparison`.
- **`Response`** — `Version`, `ID`, `IssueInstant`, `Destination`,
  `InResponseTo`, `Issuer`, `Status/StatusCode = Success`.
- **`Assertion`** — `Issuer`; `Subject/NameID` (with `Format`,
  `SPNameQualifier`); `SubjectConfirmation` (bearer) with
  `SubjectConfirmationData` (`InResponseTo`, `NotOnOrAfter`, `Recipient`,
  `NotBefore`, `Address`); `Conditions` (`NotBefore`, `NotOnOrAfter`) +
  `AudienceRestriction`; `AuthnStatement` (`AuthnInstant`, `SessionIndex`,
  `SessionNotOnOrAfter`, `AuthnContextClassRef`); `AttributeStatement`.
- **NameID formats** — `persistent` (default), `transient`, `emailAddress`,
  `unspecified`, `entity`, `kerberos`, `WindowsDomainQualifiedName`.
- **AuthnContext classes** — `PasswordProtectedTransport` (default),
  `Password`, `unspecified`, `X509`, `Kerberos`.
- **Attributes** — `NameFormat` `…:attrname-format:basic`, optional
  `FriendlyName`, multiple `<AttributeValue>`s, values typed `xs:string`.
- **Signatures** — enveloped `ds:Signature`, `rsa-sha256`
  (RSASSA-PKCS1-v1_5 / SHA-256), SHA-256 digests, **exclusive** C14N
  (`xml-exc-c14n`). The assertion and/or the response can be signed.
- **Metadata** — `EntityDescriptor` (`entityID`, `validUntil`);
  `IDPSSODescriptor` (`protocolSupportEnumeration`, `WantAuthnRequestsSigned`);
  `KeyDescriptor use="signing"`; all `NameIDFormat`s; `SingleSignOnService`
  (redirect + post); `Organization`.
- **Keys** — RSA-2048 / SHA-256 self-signed X.509 certificate.

### Not implemented

- `AuthnRequest` signature verification (`WantAuthnRequestsSigned` is advisory
  only — advertise it only if your SP allows unsigned requests).
- HTTP-POST and HTTP-Artifact bindings for the `AuthnRequest` (Redirect only).
- Single Logout (SLO), `LogoutRequest`/`LogoutResponse`.
- Attribute/assertion query profiles.
- Encrypted assertions/attributes.

## OpenID Connect spec support

### Implemented

- **Discovery** (`/.well-known/openid-configuration`) and **JWKS**.
- **OAuth 2.0 implicit flow only** — `response_type=id_token` and
  `id_token token`.
- **`response_mode`** — `fragment` (default), `query`, `form_post`.
- **Scopes** — `openid` (required), `profile`, `email`, `groups`.
- **`id_token` claims** — `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`,
  `nonce`; `profile` → `name`, `given_name`, `family_name`,
  `preferred_username`, `groups`; `email` → `email`, `email_verified`.
- **`access_token`** — JWT when `token` is requested; `token_type=Bearer`,
  `expires_in`.
- **Signing** — RS256 (RSASSA-PKCS1-v1_5 / SHA-256); public key published at
  `/oidc/jwks.json`, so the `id_token` verifies against discovery.
- **Validation** — requires the `openid` scope; rejects `response_type=code`;
  echoes `state`; passes through `nonce`.

### Not implemented (needs a server / back channel)

- **Authorization-code flow** — there is **no `token_endpoint`**, so no code
  exchange and no PKCE. A static host cannot accept the server-to-server token
  request, which is why this is implicit-only.
- Refresh tokens, UserInfo endpoint, token introspection, token revocation.
- Request objects (`request` / `request_uri`), dynamic client registration.
- Encrypted tokens (JWE) — the `id_token` is signed (JWS) only.

> OIDC endpoints and claims are described in more detail in
> [`oidc/README.md`](oidc/README.md).
