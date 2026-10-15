# Mock SAML IdP

A small, **fully client-side** mock SAML 2.0 Identity Provider for integration
testing. It runs entirely in the browser (no backend), so it can be hosted as a
static site on **GitHub Pages** or any static host.

It can:

- Accept an SP-initiated `AuthnRequest` (HTTP-Redirect binding) and pick up the
  ACS URL, issuer and `InResponseTo` automatically.
- Show a login form that populates the identity attributes (NameID, email,
  name, roles, custom attributes) and timestamps.
- Generate a **signed** SAML `Response` / `Assertion` (RSA-SHA256, exclusive
  canonicalization, enveloped signature) and POST it to the SP with the
  HTTP-POST binding.
- Serve **IdP metadata** (`metadata.xml`) and a self-signed **X.509 signing
  certificate** (`idp-cert.pem`).

> ⚠️ **Not for production.** The bundled demo private key is public and is only
> meant for local integration testing.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Using the app](#using-the-app)
  - [UI at a glance](#ui-at-a-glance)
  - [IdP-initiated login](#idp-initiated-login-start-at-the-mock-idp)
  - [SP-initiated login](#sp-initiated-login-start-at-your-sp)
  - [The result panel](#the-result-panel)
- [Configuring your Service Provider](#configuring-your-service-provider)
- [What the assertion contains](#what-the-assertion-contains)
- [Configuration reference](#configuration-reference)
- [Deploying to GitHub Pages](#deploying-to-github-pages)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Project layout](#project-layout)

## Requirements

- A recent Chromium / Firefox / Safari (needs Web Crypto and
  `DecompressionStream`).
- The page must be served over `https://` or `http://localhost` — `file://`
  will not work.

## Quick start

```bash
npm install        # only needed for the dev tooling / to rebuild vendor.js
npm run serve      # python3 -m http.server 8080  →  http://localhost:8080/
```

You do **not** need to build anything to run the app: `vendor.js` is pre-built
and committed. `npm install` is only needed for `npm test`, `npm run build`,
etc.

Then either:

- open the app, go to **Configuration**, set your SP's **ACS URL** and
  **Audience**, and use the **Sign in** tab; or
- start the login from your SP (SP-initiated) and let it fill those in for you.

## Using the app

### UI at a glance

| Tab | What it's for |
| --- | --- |
| **Sign in** | The fake IdP login screen. Fill in the identity and POST the signed response. |
| **Configuration** | IdP entity ID, SSO URL, default ACS/audience, signing options, TTLs. Saved to `localStorage`. |
| **Metadata** | View / download / copy the SAML IdP metadata XML. |
| **Certificate** | View / download / copy the signing certificate and public key; regenerate keys. |
| **About** | Summary and security note. |

Tabs are also addressable via the URL hash, e.g. `#config`, `#metadata`,
`#certificate`.

### IdP-initiated login (start at the mock IdP)

1. Open the app (**Sign in** tab).
2. Fill in the form:
   - **NameID / Username** and **NameID Format** — the subject identifier sent
     to the SP.
   - **Email**, **First name**, **Last name**, **Roles** — these become
     attributes (see [the table below](#attributes)).
   - **Additional attributes** — free-form `name → value` pairs. Multiple values
     are comma separated.
   - **SP ACS URL** — where the SP expects the response to be POSTed.
   - **Audience / SP Entity ID** — the SP's entity ID (goes in
     `Conditions/AudienceRestriction`).
3. Press **Sign in & POST response** to build the signed response and POST it
   to the ACS URL, or **Generate & preview** to inspect it without leaving the
   page.

### SP-initiated login (start at your SP)

1. In your SP's SAML settings, set the **IdP SSO URL** to the `/sso` endpoint
   (e.g. `https://<owner>.github.io/<repo>/sso`).
2. When you click "Sign in with SAML" on the SP, it redirects the browser to:

   ```
   https://<owner>.github.io/<repo>/sso?SAMLRequest=<deflate+base64>&RelayState=...
   ```

   The `/sso` page is a tiny static callback that forwards to the app
   (`…/<repo>/`), preserving the query string — GitHub Pages can't run server
   routes, so this is how the endpoint is mocked. The app root also accepts
   `?SAMLRequest=…` directly.

3. The app decodes the `AuthnRequest` and shows a banner with the detected
   **SP Entity ID**, **ACS URL** and **InResponseTo**, pre-filling the form.
4. Fill in / adjust the identity, then press **Sign in & POST response**. The
   response is POSTed back to the ACS URL with the original `RelayState`.

### The result panel

After generating a response you get:

- **POST to ACS** — send it again.
- **Download XML** / **Download base64** — save the raw response.
- **Copy base64** — copy the exact `SAMLResponse` value.
- **Verify signature** — re-validate the signature in-browser.
- **Toggle pretty** — switch the XML viewer between pretty and compact (display
  only — the signed bytes never change).

The compact XML shown is exactly what gets signed and posted.

## Configuring your Service Provider

There are two ways to wire the SP to this IdP.

### Option A — use the metadata (recommended)

Give the SP the metadata URL:

```
https://<owner>.github.io/<repo>/metadata.xml
```

The metadata points the SP at the `/sso` endpoint and includes the public
signing certificate, so no separate certificate copy-paste is needed.

You can also open the **Metadata** tab to preview it, **Download metadata.xml**,
host it yourself, and point the SP at it.

### Option B — configure manually

Provide these values in the SP:

| Setting | Value |
| --- | --- |
| IdP Entity ID / Issuer | The page base URL, e.g. `https://<owner>.github.io/<repo>/` (or whatever you set in **Configuration**). |
| IdP SSO URL | The `/sso` endpoint, e.g. `https://<owner>.github.io/<repo>/sso` |
| IdP Certificate | The PEM from the **Certificate** tab (or `idp-cert.pem`). |
| ACS URL | Your SP's assertion consumer endpoint (entered in the app). |
| Audience / SP Entity ID | Your SP's entity ID (entered in the app). |

The **IdP Entity ID** and **SSO URL** must match what the SP expects, otherwise
the SP will reject the response as coming from the wrong issuer.

## What the assertion contains

### NameID

The value you type in **NameID / Username**, with the selected **NameID Format**.
Available formats:

`persistent` (default), `transient`, `emailAddress`, `unspecified`, `entity`,
`kerberos`, `WindowsDomainQualifiedName`.

### Attributes

These are derived from the form fields automatically:

| Attribute name | Source |
| --- | --- |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | Email |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | First name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | Last name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | First + last name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier` | NameID |
| `Role` | Roles (multiple values) |

Anything you add under **Additional attributes** is also emitted. Each row's
value is split on commas into multiple `<AttributeValue>`s, so
`groups = admins, users` produces two values.

All attribute values are emitted as `xsi:type="xs:string"`.

### Timestamps & conditions

- `IssueInstant` = now.
- `Conditions/@NotBefore` = now − 5s, `@NotOnOrAfter` = now + **Assertion TTL**.
- `SubjectConfirmationData/@NotOnOrAfter` = now + **Assertion TTL**, with
  `Recipient` = ACS URL and `InResponseTo` from the request (when present).
- `AuthnStatement/@SessionNotOnOrAfter` = now + **Session TTL**.

## Configuration reference

| Field | Meaning | Default |
| --- | --- | --- |
| **IdP Entity ID** | Issuer / entityID of this IdP. | page URL |
| **IdP SSO URL** | SSO endpoint advertised in metadata (`/sso` callback). | page URL + `sso` |
| **Default ACS URL** | Where to POST if the request/field doesn't specify one. | empty |
| **Default Audience / SP Entity ID** | Default audience/issuer expected by the SP. | empty |
| **NameID Format** | Default NameID format. | `persistent` |
| **AuthnContext Class** | `AuthnContextClassRef` value. | `PasswordProtectedTransport` |
| **Display name** | Optional organization name in metadata. | `Mock SAML IdP` |
| **Assertion TTL (s)** | Lifetime of the assertion/conditions. | `300` |
| **Session TTL (s)** | `SessionNotOnOrAfter`. | `3600` |
| **POST target** | Post into the same window (`_self`) or a new one (`_blank`). | `_self` |
| **Sign the assertion** | Wrap the `Assertion` in an enveloped signature. | on |
| **Sign the response** | Wrap the whole `Response` in an enveloped signature. | off |

At least one of *Sign the assertion* / *Sign the response* should be on for real
SPs.

## Deploying to GitHub Pages

Everything needed at runtime is static and committed (including the pre-built
`vendor.js`), so you publish the repo root directly:

1. Push to `main`.
2. **Settings → Pages → Build and deployment → Source = "Deploy from a branch"**,
   then select **Branch: `main`** and **Folder: `/ (root)`** and save.

The `.nojekyll` file is included so the files are served as-is. After a minute
the site is at `https://<owner>.github.io/<repo>/`.

A ready-to-serve `metadata.xml` (and `idp-cert.pem`) for this project's Pages
URL is committed, so you can point your SP at:

```
https://mtbottle.github.io/mock_saml_server/metadata.xml
```

The app's default **IdP Entity ID** (the page URL) and **SSO URL** (the page URL
+ `sso`) are derived from its own location, so they match the committed metadata
out of the box.

If you rename the repo, move it to a different owner, or serve it from a custom
domain, regenerate the metadata for the new URL:

```bash
SSO_URL=https://new-url/sso IDP_ENTITY_ID=https://new-url/ npm run gen:metadata
```

> Prefer GitHub Actions instead of branch deploy? Add `.github/workflows/`
> back and enable **Source = "GitHub Actions"** — Pages must be enabled in the
> repo settings first (the workflow cannot create the Pages site on its own).

## Testing

```bash
npm test
```

Runs a Node harness that exercises the same `saml.js` used in the browser and
verifies every scenario (assertion-only, response-only, both, unsigned) with two
independent implementations — `xmldsigjs` and `xml-crypto` — plus metadata and
`AuthnRequest` parsing/decoding.

There is also a browser self-test at `test/browser-selftest.html` — open it while
running `npm run serve`.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| SP reports **invalid signature** | The SP is configured with a different certificate than the one signing. Copy the cert from the **Certificate** tab again, or re-download metadata. If you regenerated keys, update the SP. |
| SP reports **audience / recipient mismatch** | Set **Audience / SP Entity ID** and **ACS URL** to exactly what the SP expects. SP-initiated flows fill these in automatically. |
| SP reports **issuer mismatch** | Set **IdP Entity ID** to the value the SP is configured with. |
| SP reports **assertion expired / not yet valid** | Clock skew between machines, or a very small **Assertion TTL**. Increase the TTL, ensure clocks are synced. |
| **Nothing happens on POST** | Check the **ACS URL** is correct and reachable; a popup blocker may block a `_blank` target — switch **POST target** to `_self`. |
| App shows a **warning banner** | You're on `file://` or a non-secure origin, or the browser lacks Web Crypto / `DecompressionStream`. Serve over `https://` or `http://localhost`. |
| **Incoming SAMLRequest can't be parsed** | Some SPs POST the `AuthnRequest` instead of redirecting; this tool handles the HTTP-Redirect (deflate) binding only. |
| SP requires a **signed AuthnRequest** | This IdP does not verify AuthnRequest signatures; only advertise it if your SP allows unsigned requests. |

## Development

```bash
npm install
npm run build          # rebuild vendor.js (xmldsigjs + @peculiar/x509) from src/vendor-entry.js
npm test               # verify generated signatures (xmldsigjs + independent xml-crypto)
npm run gen:key        # regenerate the bundled demo key/cert
npm run gen:metadata   # emit metadata.xml + idp-cert.pem for a given SSO_URL
npm run serve          # static file server on :8080
```

`vendor.js` is pre-built and committed so the site needs no build step to run.
`npm run build` regenerates it after dependency changes.

### How signing works

Signatures are produced with
[xmldsigjs](https://github.com/PeculiarVentures/xmldsigjs) on top of Web Crypto,
and certificates with
[@peculiar/x509](https://github.com/PeculiarVentures/x509). The `SignedInfo` is
canonicalized with **exclusive** C14N so the signature does not depend on
namespaces inherited from an ancestor element (this matters when signing a
nested `Assertion`). References use the enveloped-signature + exclusive-C14N
transforms.

### Bundled demo key

`idp-key.json` holds a throwaway RSA-2048 key + self-signed certificate used by
default, so `metadata.xml` / `idp-cert.pem` are stable. In the app you can
**Regenerate key pair** (stored in `localStorage`) and later **Use bundled demo
key** to switch back. Regenerate the committed key with `npm run gen:key`.

## Project layout

```
index.html          UI
sso/index.html      /sso callback endpoint (forwards to the app)
styles.css          styles
app.js              UI logic, routing, HTTP-POST
saml.js             SAML XML building, signing, metadata, AuthnRequest parsing
vendor.js           pre-built bundle of xmldsigjs + @peculiar/x509
src/vendor-entry.js bundle entry point
scripts/            key + static metadata generators
test/               Node verification harness + browser self-test
```
