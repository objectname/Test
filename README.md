# Private Proxy Test

A single-user, experimental HTTPS browsing proxy for Cloudflare Workers.

The login page asks for the password only. The password is supplied by the Worker secret `PROXY_PASSWORD`; it is never stored in the source code.

Destination cookies are stored as an encrypted JSON envelope using AES-256-GCM. The encryption key is derived from `PROXY_PASSWORD` with PBKDF2-SHA256.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Create a KV namespace:

```bash
npx wrangler kv namespace create COOKIE_STORE
```

3. Put the returned namespace ID into `wrangler.toml`.

4. Set the temporary password secret:

```bash
npx wrangler secret put PROXY_PASSWORD
```

Enter your temporary password when prompted. For this test, you may use `Olympus`, but change it before real use.

5. Run locally:

```bash
npm run dev
```

6. Deploy:

```bash
npm run deploy
```

## Cookie controls

- `Clear saved cookies` deletes the encrypted cookie jar.
- There is intentionally no password-recovery endpoint.
- If you forget the password, delete the KV key `encrypted_cookie_jar` and set a new `PROXY_PASSWORD`; saved destination sessions become unrecoverable.

## Limits

This is a test build, not a secure general-purpose browser. It uses minimal HTML rewriting, an in-memory login-session store, and does not fully isolate every destination website. Avoid primary email, banking, payment, and password-manager accounts.
