// Direct-browser launcher with blacklist.
// The Worker supplies the interface and checks blocked domains only.
// Safari opens allowed HTTPS websites directly.

const SESSION_COOKIE = "proxy_session";
const sessions = new Set();

const encoder = new TextEncoder();

// Add domains you want to block. Do not include "https://" or paths.
const DEFAULT_BLOCKED_DOMAINS = [
  "example-blocked-site.com"
];

function b64encode(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
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

function getBlockedDomains(env) {
  const raw = env.BLOCKED_DOMAINS || "";

  const configured = raw
    .split(",")
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);

  return [...new Set([...DEFAULT_BLOCKED_DOMAINS, ...configured])];
}

function isBlocked(targetUrl, blockedDomains) {
  try {
    const parsed = new URL(targetUrl);

    if (parsed.protocol !== "https:") {
      return true;
    }

    const host = parsed.hostname.toLowerCase();

    return blockedDomains.some(domain => {
      return host === domain || host.endsWith("." + domain);
    });
  } catch {
    return true;
  }
}

function getSession(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/(?:^|;\s*)proxy_session=([^;]+)/);
  const token = match ? decodeURIComponent(match[1]) : null;

  return token && sessions.has(token) ? token : null;
}

function sessionCookie(token, clear = false) {
  const value = clear ? "" : token;
  const expires = clear
    ? "Thu, 01 Jan 1970 00:00:00 GMT"
    : "Max-Age=86400";

  return `proxy_session=${value}; Path=/; ${expires}; Secure; HttpOnly; SameSite=Lax`;
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
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Private Launcher</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      background: #101418;
      color: #e8edf2;
      display: grid;
      place-items: center;
      min-height: 100vh;
      margin: 0;
    }

    main {
      background: #182028;
      padding: 28px;
      border-radius: 14px;
      width: min(360px, 90vw);
    }

    input,
    button {
      width: 100%;
      padding: 11px;
      border-radius: 8px;
      border: 1px solid #33414f;
      margin-top: 10px;
      box-sizing: border-box;
    }

    button {
      background: #2f81f7;
      color: white;
      border: 0;
      font-weight: 600;
    }

    .error {
      color: #ff8181;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <main>
    <h1>Private Launcher</h1>

    <form method="post" action="/login">
      <label for="password">Password</label>
      <input
        id="password"
        name="password"
        type="password"
        autocomplete="current-password"
        required
      >

      <button type="submit">Unlock</button>

      ${message ? `<p class="error">${message}</p>` : ""}
    </form>
  </main>
</body>
</html>`;

  return htmlResponse(html);
}

function homePage() {
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Private Launcher</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      background: #101418;
      color: #e8edf2;
      margin: 0;
      padding: 24px;
    }

    main {
      max-width: 720px;
      margin: auto;
    }

    input,
    button {
      padding: 12px;
      border-radius: 8px;
      border: 1px solid #33414f;
      box-sizing: border-box;
    }

    input {
      width: 100%;
      background: #182028;
      color: #e8edf2;
    }

    button {
      background: #2f81f7;
      color: white;
      border: 0;
      font-weight: 600;
      margin-top: 10px;
      width: 100%;
    }

    .danger {
      background: #b62324;
      margin-top: 16px;
    }

    #status {
      margin-top: 12px;
      min-height: 22px;
    }

    .blocked {
      color: #ff8181;
    }

    .allowed {
      color: #7ee787;
    }
  </style>
</head>
<body>
  <main>
    <h1>Open a website directly</h1>

    <form onsubmit="openSite(event)">
      <input
        id="url"
        type="url"
        placeholder="https://example.com"
        required
      >

      <button type="submit">Open</button>
    </form>

    <div id="status"></div>

    <form method="post" action="/logout">
      <button class="danger" type="submit">Lock launcher</button>
    </form>

    <p>
      Safari opens allowed HTTPS websites directly.
      The server only checks the blacklist.
    </p>
  </main>

  <script>
    async function openSite(event) {
      event.preventDefault();

      const status = document.getElementById("status");
      const url = document.getElementById("url").value;

      status.className = "";
      status.textContent = "Checking blacklist...";

      const response = await fetch("/check?url=" + encodeURIComponent(url));
      const result = await response.json();

      if (result.blocked) {
        status.className = "blocked";
        status.textContent = "Blocked: " + result.reason;
        return;
      }

      status.className = "allowed";
      status.textContent = "Opening directly...";
      window.open(url, "_blank", "noopener");
    }
  </script>
</body>
</html>`;

  return htmlResponse(html);
}

export default {
  async fetch(request, env) {
    const password = env.PROXY_PASSWORD;

    if (!password) {
      return new Response("Missing PROXY_PASSWORD secret", {
        status: 500
      });
    }

    const url = new URL(request.url);
    const session = getSession(request);

    if (url.pathname === "/login" && request.method === "POST") {
      const form = await request.formData();
      const supplied = form.get("password") || "";

      if (!constantTimeEqual(supplied, password)) {
        return loginPage("Incorrect password.");
      }

      const token = randomB64(32);
      sessions.add(token);

      return htmlResponse(
        `<meta http-equiv="refresh" content="0;url=/">`,
        303,
        {
          "Set-Cookie": sessionCookie(token)
        }
      );
    }

    if (url.pathname === "/logout" && request.method === "POST") {
      if (session) {
        sessions.delete(session);
      }

      return htmlResponse(
        `<meta http-equiv="refresh" content="0;url=/">`,
        303,
        {
          "Set-Cookie": sessionCookie("", true)
        }
      );
    }

    if (!session) {
      return loginPage("Please sign in.");
    }

    if (url.pathname === "/" && request.method === "GET") {
      return homePage();
    }

    if (url.pathname === "/check" && request.method === "GET") {
      const target = url.searchParams.get("url") || "";
      const blockedDomains = getBlockedDomains(env);

      if (!target) {
        return Response.json({
          blocked: true,
          reason: "No URL provided"
        });
      }

      if (isBlocked(target, blockedDomains)) {
        return Response.json({
          blocked: true,
          reason: "Only HTTPS websites outside the blacklist are allowed"
        });
      }

      return Response.json({
        blocked: false,
        reason: "Allowed"
      });
    }

    return htmlResponse("<h1>Not found</h1>", 404);
  }
};
