// Shared OIDC/JWT helpers for the static mock provider.
//
// Runs in the browser (Web Crypto) and in Node (global crypto + TextEncoder +
// btoa/atob), so the same code can be unit-tested without a build step.

export const DEFAULT_USER = {
  sub: "user-1",
  email: "user@example.com",
  email_verified: true,
  name: "Ada Lovelace",
  given_name: "Ada",
  family_name: "Lovelace",
  preferred_username: "ada",
  groups: ["users", "admins"],
};

const CLAIMS_BY_SCOPE = {
  profile: ["name", "given_name", "family_name", "preferred_username", "groups"],
  email: ["email", "email_verified"],
  groups: ["groups"],
};

export function b64url(input) {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToBytes(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function unb64url(str) {
  return new TextDecoder().decode(b64urlToBytes(str));
}

export async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

export async function importPublicJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"]
  );
}

export async function signJwt(payload, key, kid) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
  const body = b64url(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${b64url(signature)}`;
}

export async function verifyJwt(token, jwk) {
  const [h, b, s] = String(token).split(".");
  if (!h || !b || !s) throw new Error("malformed token");
  const key = await importPublicJwk(jwk);
  const ok = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    b64urlToBytes(s),
    new TextEncoder().encode(`${h}.${b}`)
  );
  if (!ok) throw new Error("bad signature");
  return JSON.parse(unb64url(b));
}

export function claimsForScope(user, scope) {
  const claims = {};
  for (const s of scope) {
    for (const c of CLAIMS_BY_SCOPE[s] || []) {
      if (user[c] !== undefined) claims[c] = user[c];
    }
  }
  return claims;
}

export function normalizeScope(raw) {
  const scope = String(raw || "openid").split(/\s+/).filter(Boolean);
  return scope.length ? scope : ["openid"];
}

/**
 * Build an id_token payload (not yet signed).
 */
export function buildIdTokenPayload({ issuer, clientId, user, scope, nonce, authTime, ttlSeconds }) {
  const iat = Math.floor(Date.now() / 1000);
  return {
    iss: issuer,
    sub: user.sub,
    aud: clientId,
    exp: iat + (ttlSeconds ?? 3600),
    iat,
    auth_time: authTime ?? iat,
    ...(nonce ? { nonce } : {}),
    ...claimsForScope(user, scope),
  };
}

export function buildAccessTokenPayload({ issuer, clientId, user, scope, ttlSeconds }) {
  const iat = Math.floor(Date.now() / 1000);
  return {
    iss: issuer,
    sub: user.sub,
    aud: clientId,
    exp: iat + (ttlSeconds ?? 3600),
    iat,
    scope: scope.join(" "),
    typ: "access",
  };
}

/**
 * Pick a user from the request params. `login_hint` (or explicit overrides)
 * are matched against sub/email/preferred_username; anything else falls back
 * to the default user. Extra `sub`/`email`/`name` params let you shape a
 * throwaway identity inline.
 */
export function userFromParams(params) {
  const user = { ...DEFAULT_USER };
  for (const key of ["sub", "email", "name", "given_name", "family_name", "preferred_username"]) {
    const v = params.get(key);
    if (v) user[key] = v;
  }
  if (params.get("login_hint") && !user.email) user.email = params.get("login_hint");
  if (params.get("groups")) {
    user.groups = params.get("groups").split(",").map((s) => s.trim()).filter(Boolean);
  }
  return user;
}

export async function loadJson(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`failed to load ${url}: ${res.status}`);
  return res.json();
}
