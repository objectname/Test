
// Experimental personal HTTPS browsing proxy.
// Login asks for the password only. The password comes from the
// Cloudflare Worker secret named PROXY_PASSWORD.

const SESSION_COOKIE = "proxy_session";
const JAR_KEY = "encrypted_cookie_jar";

// Basic in-memory session store. This resets when the Worker restarts;
// that is acceptable for a single-user test build.
const sessions = new Set();

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64encode(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(text) {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function randomB64(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return b64encode(bytes);
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  const len = Math.max(aa.length, bb.length);
  let diff = aa.length ^ bb.length;
  for (let i = 0; i < len; i++) {
    diff |= (aa[i] || 0) ^ (bb[i] || 0);
  }
  return diff === 0;
}

async function deriveKey(password, saltBytes) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 210000,
      hash: "SHA-256"
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(value, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const plaintext = encoder.encode(JSON.stringify(value));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext)
  );
  return {
    version: 1,
    algorithm: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: 210000,
    salt: b64encode(salt),
    iv: b64encode(iv),
    ciphertext: b64encode(encrypted)
  };
}

async function decryptEnvelope(envelope, password) {
  if (!envelope || envelope.algorithm !== "AES-GCM") {
    throw new Error("Unsupported cookie-jar format");
  }
  const key = await deriveKey(password, b64decode(envelope.salt));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(envelope.iv) },
    key,
    b64decode(envelope.ciphertext)
  );
  return JSON.parse(decoder.decode(decrypted));
}

function getSession(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|;\\s*)" + SESSION_COOKIE + "=([^;]+)"));
  const token = match ? decodeURIComponent(match[1]) : null;
  return token && sessions.has(token) ? token : null;
}

function sessionCookie(token, clear = false) {
  const value = clear ? "" : token;
  const expires = clear ? "Thu, 01 Jan 1970 00:00:00 GMT" : "Max-Age=86400";
  return `${SESSION_COOKIE}=${value}; Path=/; ${expires}; Secure; HttpOnly; SameSite=Lax`;
}

function htmlResponse(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function loginPage(message = "") {
  return htmlResponse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Proxy Login</title>
<style>
body{font-family:system-ui,sans-serif;background:#101418;color:#e8edf2;display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#182028;padding:28px;border-radius:14px;width:min(360px,90vw)}
input,button{width:100%;padding:11px;border-radius:8px;border:1px solid #33414f;margin-top:10px;box-sizing:border-box}
button{background:#2f81f7;color:white;border:0;font-weight:600}
.error{color:#ff8181;margin-top:10px}
</style></head>
<body><main>
<h1>Private Proxy</h1>
<form method="post" action="/login">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Unlock</button>
${message ? `<p class="error">${message}</p>` : ""}
</form>
</main></body></html>`);
}

function homePage() {
  return htmlResponse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Proxy</title>
<style>
body{font-family:system-ui,sans-serif;background:#101418;color:#e8edf2;margin:0;padding:24px}
main{max-width:760px;margin:auto}
input,button{padding:11px;border-radius:8px;border:1px solid #33414f;box-sizing:border-box}
input{width:100%;background:#182028;color:#e8edf2}
button{background:#2f81f7;color:white;border:0;font-weight:600;margin-top:10px;width:100%}
.danger{background:#b62324;margin-top:16px}
form{margin-top:18px}
</style></head>
<body><main>
<h1>Private browsing proxy</h1>
<form method="get" action="/proxy">
<input name="url" type="url" placeholder="https://example.com" required>
<button type="submit">Open through proxy</button>
</form>
<form method="post" action="/cookies/clear" onsubmit="return confirm('Delete all saved destination cookies and sessions?')">
<button class="danger" type="submit">Clear saved cookies</button>
</form>
<p>HTTPS is enforced. Saved destination cookies are encrypted at rest with AES-GCM.</p>
</main></body></html>`);
}

function normalizeDestination(raw) {
  let value;
  try {
    value = new URL(raw);
  } catch {
    return null;
  }
  if (value.protocol !== "https:") return null;
  return value;
}

function cookieMatches(cookie, requestUrl) {
  const requestHost = requestUrl.hostname;
  const cookieDomain = cookie.domain.replace(/^\./, "");
  const domainOk = cookie.hostOnly
    ? requestHost === cookieDomain
    : requestHost === cookieDomain || requestHost.endsWith("." + cookieDomain);
  const path = requestUrl.pathname || "/";
  const pathOk = path.startsWith(cookie.path || "/");
  return domainOk && pathOk;
}

function serializeCookie(cookie) {
  let result = `${cookie.name}=${cookie.value}`;
  result += `; Path=${cookie.path || "/"}`;
  if (cookie.domain) result += `; Domain=${cookie.domain}`;
  if (cookie.secure) result += "; Secure";
  if (cookie.httpOnly) result += "; HttpOnly";
  if (cookie.sameSite) result += `; SameSite=${cookie.sameSite}`;
  return result;
}

function parseSetCookie(header, requestUrl) {
  const parts = header.split(";");
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf("=");
  if (eq < 1) return null;
  const cookie = {
    name: nameValue.slice(0, eq).trim(),
    value: nameValue.slice(eq + 1).trim(),
    domain: requestUrl.hostname,
    hostOnly: true,
    path: "/",
    secure: false,
    httpOnly: false,
    sameSite: "Lax",
    expires: null
  };
  for (const attr of attrs) {
    const [rawKey, rawValue = ""] = attr.trim().split("=");
    const key = rawKey.toLowerCase();
    if (key === "domain") {
      cookie.domain = rawValue.trim();
      cookie.hostOnly = false;
    } else if (key === "path") {
      cookie.path = rawValue || "/";
    } else if (key === "secure") {
      cookie.secure = true;
    } else if (key === "httponly") {
      cookie.httpOnly = true;
    } else if (key === "samesite") {
      cookie.sameSite = rawValue || "Lax";
    } else if (key === "expires") {
      const date = Date.parse(rawValue);
      if (!Number.isNaN(date)) cookie.expires = date;
    } else if (key === "max-age") {
      const seconds = Number(rawValue);
      if (!Number.isNaN(seconds)) cookie.expires = Date.now() + seconds * 1000;
    }
  }
  return cookie;
}

function rewriteHtml(html, destination, proxyBase) {
  // Minimal test-only rewriting for common navigation and resource attributes.
  return html
    .replace(/(href|src|action)=["']([^"']+)["']/gi, (match, attr, url) => {
      if (/^(javascript:|data:|mailto:|#)/i.test(url)) return match;
      try {
        const resolved = new URL(url, destination);
        if (resolved.protocol !== "https:") return match;
        return `${attr}="${proxyBase}/proxy?url=${encodeURIComponent(resolved.href)}"`;
      } catch {
        return match;
      }
    });
}

async function readJar(env, password) {
  if (!env.COOKIE_STORE) return { cookies: [] };
  const envelope = await env.COOKIE_STORE.get(JAR_KEY, "json");
  if (!envelope) return { cookies: [] };
  try {
    return await decryptEnvelope(envelope, password);
  } catch {
    return { cookies: [] };
  }
}

async function writeJar(env, jar, password) {
  if (!env.COOKIE_STORE) return;
  const envelope = await encryptJson(jar, password);
  await env.COOKIE_STORE.put(JAR_KEY, JSON.stringify(envelope));
}

async function handleProxy(request, env, password, url) {
  const destination = normalizeDestination(url);
  if (!destination) {
    return htmlResponse("<h1>HTTPS URLs only</h1><p><a href=\"/\">Back</a></p>", 400);
  }

  const jar = await readJar(env, password);
  jar.cookies = (jar.cookies || []).filter(
    c => !c.expires || c.expires > Date.now()
  );

  const cookieHeader = jar.cookies
    .filter(c => cookieMatches(c, destination))
    .map(serializeCookie)
    .join("; ");

  const headers = new Headers();
  headers.set("User-Agent", request.headers.get("User-Agent") || "Mozilla/5.0");
  headers.set("Accept", request.headers.get("Accept") || "*/*");
  headers.set("Accept-Language", request.headers.get("Accept-Language") || "en-US,en;q=0.9");
  if (cookieHeader) headers.set("Cookie", cookieHeader);

  let upstream;
  try {
    upstream = await fetch(destination, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual"
    });
  } catch {
    return htmlResponse("<h1>Could not reach destination</h1><p><a href=\"/\">Back</a></p>", 502);
  }

  const responseHeaders = new Headers();
  for (const [name, value] of upstream.headers) {
    if (["set-cookie", "content-security-policy", "x-frame-options", "content-encoding", "content-length", "location"].includes(name.toLowerCase())) continue;
    responseHeaders.set(name, value);
  }

  const setCookies = upstream.headers.getSetCookie ? upstream.headers.getSetCookie() : [];
  for (const raw of setCookies) {
    const cookie = parseSetCookie(raw, destination);
    if (!cookie) continue;
    jar.cookies = jar.cookies.filter(
      c => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path)
    );
    if (!cookie.expires || cookie.expires > Date.now()) jar.cookies.push(cookie);
  }
  await writeJar(env, jar, password);

  const location = upstream.headers.get("location");
  if (location) {
    try {
      const next = new URL(location, destination);
      if (next.protocol === "https:") {
        responseHeaders.set("Location", `/proxy?url=${encodeURIComponent(next.href)}`);
      }
    } catch {}
  }

  const contentType = upstream.headers.get("content-type") || "";
  let body = upstream.body;
  if (contentType.includes("text/html")) {
    const html = await upstream.text();
    body = rewriteHtml(html, destination, new URL(request.url).origin);
  }

  return new Response(body, {
    status: upstream.status,
    headers: responseHeaders
  });
}

export default {
  async fetch(request, env) {
    const password = env.PROXY_PASSWORD;
    if (!password) {
      return new Response("Missing PROXY_PASSWORD secret", { status: 500 });
    }

    const url = new URL(request.url);
    const session = getSession(request);

    if (url.pathname === "/login" && request.method === "POST") {
      const form = await request.formData();
      const supplied = form.get("password") || "";
      if (!constantTimeEqual(supplied, password)) {
        return htmlResponse(loginPage("Incorrect password."), 401);
      }
      const token = randomB64(32);
      sessions.add(token);
      return htmlResponse(`<meta http-equiv="refresh" content="0;url=/">`, 303, {
        "Set-Cookie": sessionCookie(token)
      });
    }

    if (url.pathname === "/logout" && request.method === "POST") {
      if (session) sessions.delete(session);
      return htmlResponse(`<meta http-equiv="refresh" content="0;url=/">`, 303, {
        "Set-Cookie": sessionCookie("", true)
      });
    }

    if (!session) {
      if (url.pathname === "/" && request.method === "GET") return loginPage();
      return htmlResponse(loginPage("Please sign in."), 401);
    }

    if (url.pathname === "/" && request.method === "GET") return homePage();

    if (url.pathname === "/cookies/clear" && request.method === "POST") {
      if (env.COOKIE_STORE) await env.COOKIE_STORE.delete(JAR_KEY);
      return htmlResponse(`<meta http-equiv="refresh" content="0;url=/">`, 303);
    }

    if (url.pathname === "/proxy" && request.method === "GET") {
      return handleProxy(request, env, password, url.searchParams.get("url") || "");
    }

    return htmlResponse("<h1>Not found</h1>", 404);
  }
};
