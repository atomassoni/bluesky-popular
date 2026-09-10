(function () {
  const PROD_CLIENT_ID = "https://atomassoni.github.io/bluesky-popular/oauth/client-metadata.json";
  const PROD_REDIRECT_URI = "https://atomassoni.github.io/bluesky-popular/oauth/callback";
  const PROD_APP_URL = "https://atomassoni.github.io/bluesky-popular/";
  const SCOPE = "atproto transition:generic";
  const PENDING_KEY = "bluesky-popular-oauth-pending";
  const SESSION_KEY = "bluesky-popular-oauth-session";
  let refreshPromise;

  function config() {
    if (!isLoopback()) {
      return {
        clientId: PROD_CLIENT_ID,
        redirectUri: PROD_REDIRECT_URI,
        appUrl: PROD_APP_URL,
        scope: SCOPE,
      };
    }

    const appUrl = new URL(".", location.href).toString();
    const redirectUri = new URL("oauth/callback/", appUrl).toString();
    const clientId = new URL("http://localhost");
    clientId.searchParams.set("redirect_uri", redirectUri);
    clientId.searchParams.set("scope", SCOPE);
    return { clientId: clientId.toString(), redirectUri, appUrl, scope: SCOPE };
  }

  function redirectLocalhost() {
    if (location.hostname !== "localhost") return false;
    const url = new URL(location.href);
    url.hostname = "127.0.0.1";
    location.replace(url);
    return true;
  }

  function normalizeHandle(handle) {
    return String(handle || "").trim().replace(/^@/, "").toLowerCase();
  }

  async function login(handle) {
    handle = normalizeHandle(handle);
    const oauthConfig = config();
    const did = await globalThis.resolveDidFromHandle(handle);
    if (!did) throw new Error("Could not resolve that handle.");
    if (!await globalThis.verifyDidHandle(did, handle)) {
      throw new Error("That handle did not verify against its DID document.");
    }

    const pdsEndpoint = await globalThis.getPdsEndpointForDid(did);
    const metadata = await discover(pdsEndpoint);
    const state = randomString();
    const codeVerifier = randomString(64);
    const keys = await generateKeyPair();
    const pending = {
      state,
      did,
      handle,
      pdsEndpoint,
      clientId: oauthConfig.clientId,
      redirectUri: oauthConfig.redirectUri,
      appUrl: oauthConfig.appUrl,
      scope: oauthConfig.scope,
      issuer: metadata.issuer,
      tokenEndpoint: metadata.token_endpoint,
      codeVerifier,
      publicJwk: keys.publicJwk,
      privateJwk: keys.privateJwk,
      authNonce: "",
    };

    const par = await postForm(metadata.pushed_authorization_request_endpoint, {
      client_id: oauthConfig.clientId,
      redirect_uri: oauthConfig.redirectUri,
      response_type: "code",
      scope: oauthConfig.scope,
      state,
      code_challenge: await sha256(codeVerifier),
      code_challenge_method: "S256",
      login_hint: handle,
    }, pending);

    write(PENDING_KEY, pending);
    const url = new URL(metadata.authorization_endpoint);
    url.searchParams.set("client_id", oauthConfig.clientId);
    url.searchParams.set("request_uri", par.request_uri);
    location.assign(url);
  }

  async function callback(search = location.search) {
    const params = new URLSearchParams(search);
    if (params.has("error")) {
      throw new Error(params.get("error_description") || params.get("error"));
    }

    const pending = read(PENDING_KEY);
    const state = params.get("state");
    const code = params.get("code");
    const issuer = params.get("iss");
    if (!pending || !state || !code || !issuer) throw new Error("Missing OAuth callback state.");
    if (state !== pending.state) throw new Error("OAuth state did not match.");
    if (issuer !== pending.issuer) throw new Error("OAuth issuer did not match.");

    const tokens = await postForm(pending.tokenEndpoint, {
      grant_type: "authorization_code",
      code,
      client_id: pending.clientId,
      redirect_uri: pending.redirectUri,
      code_verifier: pending.codeVerifier,
    }, pending);
    if (tokens.sub !== pending.did) throw new Error("Authorized DID did not match the requested account.");

    const session = sessionFromTokens(pending, tokens);
    write(SESSION_KEY, session);
    localStorage.removeItem(PENDING_KEY);
    return session;
  }

  async function authenticatedFetch(session, url, options = {}, retry = true) {
    try {
      return await dpopFetch(url, options, session, "resourceNonce", session.accessToken);
    } catch (error) {
      if (!retry || error.status !== 401 || !session.refreshToken) throw error;
      Object.assign(session, await refresh(session));
      return authenticatedFetch(session, url, options, false);
    }
  }

  async function refresh(session) {
    if (refreshPromise) return refreshPromise;
    refreshPromise = postForm(session.tokenEndpoint, {
      grant_type: "refresh_token",
      refresh_token: session.refreshToken,
      client_id: session.clientId,
    }, session).then(tokens => {
      if (tokens.sub && tokens.sub !== session.did) throw new Error("Refreshed session DID did not match.");
      const next = sessionFromTokens(session, tokens);
      write(SESSION_KEY, next);
      return next;
    });

    try {
      return await refreshPromise;
    } catch (error) {
      if (["invalid_grant", "invalid_token"].includes(error.body?.error)) expire();
      throw error;
    } finally {
      refreshPromise = undefined;
    }
  }

  function sessionFromTokens(previous, tokens) {
    return {
      ...previous,
      did: tokens.sub || previous.did,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || previous.refreshToken,
      scope: tokens.scope || previous.scope,
      publicJwk: previous.publicJwk,
      privateJwk: previous.privateJwk,
      authNonce: previous.authNonce || "",
      resourceNonce: previous.resourceNonce || "",
      updatedAt: Date.now(),
    };
  }

  async function discover(pdsEndpoint) {
    const origin = new URL(pdsEndpoint).origin;
    const resource = await getJson(`${origin}/.well-known/oauth-protected-resource`);
    const issuer = resource.authorization_servers?.[0] || origin;
    const metadata = await getJson(`${issuer}/.well-known/oauth-authorization-server`);
    if (!metadata.issuer || !metadata.authorization_endpoint || !metadata.token_endpoint ||
        !metadata.pushed_authorization_request_endpoint) {
      throw new Error("OAuth server metadata is incomplete.");
    }
    return metadata;
  }

  async function postForm(url, params, state) {
    return dpopFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    }, state, "authNonce");
  }

  async function dpopFetch(url, options, state, nonceKey, accessToken) {
    const method = options.method || "GET";
    let nonce = state[nonceKey] || "";

    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...(options.headers || {}),
          ...(accessToken ? { Authorization: `DPoP ${accessToken}` } : {}),
          DPoP: await createProof(url, method, nonce, accessToken, state),
        },
      });

      const nextNonce = response.headers.get("DPoP-Nonce");
      if (nextNonce) {
        state[nonceKey] = nonce = nextNonce;
        if (state.accessToken) write(SESSION_KEY, state);
      }
      if (response.ok) return parseResponse(response);

      const body = await response.json().catch(() => ({}));
      if (attempt === 0 && nextNonce && body.error === "use_dpop_nonce") continue;
      const error = new Error(body.error_description || body.message || body.error || "OAuth request failed.");
      error.status = response.status;
      error.body = body;
      throw error;
    }
  }

  async function createProof(url, method, nonce, accessToken, state) {
    const publicJwk = state.publicJwk;
    const privateKey = await crypto.subtle.importKey(
      "jwk", state.privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
    const now = Math.floor(Date.now() / 1000);
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: pick(publicJwk, "kty", "crv", "x", "y") };
    const payload = { jti: randomString(24), htm: method.toUpperCase(), htu: url, iat: now, exp: now + 300 };
    if (nonce) payload.nonce = nonce;
    if (accessToken) payload.ath = await sha256(accessToken);
    const input = `${encode(header)}.${encode(payload)}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(input)
    );
    return `${input}.${base64Url(new Uint8Array(signature))}`;
  }

  async function generateKeyPair() {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const [publicJwk, privateJwk] = await Promise.all([
      crypto.subtle.exportKey("jwk", pair.publicKey),
      crypto.subtle.exportKey("jwk", pair.privateKey),
    ]);
    return { publicJwk, privateJwk };
  }

  async function getJson(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Request failed (${response.status}).`);
    return response.json();
  }

  function parseResponse(response) {
    return (response.headers.get("content-type") || "").includes("application/json")
      ? response.json()
      : null;
  }

  async function sha256(value) {
    return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
  }

  function encode(value) {
    return base64Url(new TextEncoder().encode(JSON.stringify(value)));
  }

  function base64Url(bytes) {
    let value = "";
    for (const byte of bytes) value += String.fromCharCode(byte);
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function randomString(size = 32) {
    return base64Url(crypto.getRandomValues(new Uint8Array(size)));
  }

  function pick(source, ...keys) {
    return Object.fromEntries(keys.map(key => [key, source[key]]));
  }

  function read(key) {
    try {
      const value = JSON.parse(localStorage.getItem(key) || "null");
      if (!value) return null;
      return {
        ...value,
        issuer: value.issuer || value.authServerIssuer,
        publicJwk: value.publicJwk || value.dpopPublicJwk,
        privateJwk: value.privateJwk || value.dpopPrivateJwk,
        authNonce: value.authNonce || value.authServerNonce || "",
        resourceNonce: value.resourceNonce || value.resourceServerNonce || "",
      };
    } catch {
      localStorage.removeItem(key);
      return null;
    }
  }

  function write(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  function loadSession() {
    return read(SESSION_KEY);
  }

  function expire() {
    localStorage.removeItem(SESSION_KEY);
    dispatchEvent(new CustomEvent("bluesky-auth-expired", {
      detail: { message: "Your saved Bluesky login expired. Please log in again." },
    }));
  }

  function logout() {
    localStorage.removeItem(PENDING_KEY);
    localStorage.removeItem(SESSION_KEY);
  }

  function isLoopback() {
    return ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
  }

  globalThis.oauth = {
    callback,
    fetch: authenticatedFetch,
    loadSession,
    login,
    logout,
    normalizeHandle,
    redirectLocalhost,
  };
})();
