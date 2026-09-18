# Secret Server and Enzoic setup

Everything in here applies to **both** integrations. The PowerShell and Python
READMEs cover how to run each one; this covers what has to be true of your
Secret Server and Enzoic tenants before either will work.

- [The three values](#the-three-values)
- [The Secret Server account](#the-secret-server-account)
- [Getting an Enzoic API key](#getting-an-enzoic-api-key)
- [The API, and the version trap](#the-api-and-the-version-trap)
- [Things that cost real time](#things-that-cost-real-time)

## The three values

| Setting | Value |
|---|---|
| Base URL | `https://yourserver/SecretServer` — scheme, host, **and** the virtual directory |
| Username / password | A Secret Server account with View on the folders and secrets in scope |
| Enzoic API key | The raw 32-hex key from <https://console.enzoic.com> |

The `/SecretServer` virtual directory is required. The token endpoint is
`https://host/SecretServer/oauth2/token`, and dropping the vdir gives a 404
that looks exactly like "Enable Webservices is off".

Leave the Enzoic key blank and the sweep lists and reads the secrets without
checking any of them. That is a useful first run: it proves the Secret Server
half — connectivity, credentials, permissions — before a key is in play.

## The Secret Server account

Create a dedicated **application account** — not a person's login, and not
`ss_admin`. Admin → Users → Create New, tick **Application Account**. Per
Delinea's API spec, application accounts *"are used for automation, cannot log
in using the UI, and do not consume a user license."*

Three reasons it matters:

- **2FA.** Admin accounts are the ones that have it, and 2FA breaks the OAuth
  password grant with an HTTP 400 that looks exactly like a wrong password.
  Application accounts cannot use the UI, so 2FA never applies.
- **Audit.** Every secret the sweep reads is logged against this account.
  Keeping automation reads out of a human's session history is the difference
  between a readable audit trail and an unusable one.
- **Blast radius.** The password lives in a config file. Scoping the account
  bounds what that file is worth.

### It needs two separate grants

On each folder's **Sharing** tab, add the account and set *both*:

| Grant | Effect if missing |
|---|---|
| Folder Permissions (`folderAccessRoleName`) = **View** | The folder is invisible; there is nothing to sweep |
| Secret Permissions (`secretAccessRoleName`) = **View** | The folder appears but the sweep returns **zero secrets** |

Setting only the first is the single most common misconfiguration, and it
presents as a broken script rather than a permissions problem.

Nested folders need **Inherit Permissions** enabled, or their own grant. A
secret in a non-inheriting subfolder is invisible to the API in a way that is
indistinguishable from not existing.

The account does **not** need to be an administrator. View on the folders in
scope is enough — neither integration ever writes.

### The tradeoff to name out loud

A complete sweep needs one account that can read every password in scope, which
is precisely what a PAM deployment exists to prevent. Scope it to the folders
that actually matter, and raise it with the customer *before* proposing it
rather than after.

The corollary: **an empty result is ambiguous.** The API returns only what the
account has View on, and no-permission is indistinguishable from empty. Both
integrations say so explicitly rather than reporting a clean vault.

## Getting an Enzoic API key

Sign up at <https://console.enzoic.com> — self-service, no sales call to get
started. Create the account, then create an API key in the console. It issues a
**key** and a **secret**.

**This wants the key**: the raw 32-hex value, passed as-is.

```
POST https://api.enzoic.com/v1/passwords
Authorization: basic <raw 32-hex api key>      <- NOT base64, NOT key:secret
Content-Type: application/json

{"partialSHA256":"<first 10 hex of lowercase SHA-256 of the UTF-8 password>"}
```

- **200** → `candidates[]`, each with `sha256`, `revealedInExposure`,
  `exposureCount`. Compare the **full** hash against `candidates[].sha256`,
  case-insensitively.
- **404** → the prefix is absent → not compromised.

Do not base64 it and do not combine it with the secret, which is what Enzoic's
own SDKs use. A ~90-character `Base64(key:secret)` value 401s in every encoding;
the raw 32-hex key works immediately. A key encoded either of those ways comes
back as an HTTP 401 with a message saying exactly this.

One key per environment is the useful granularity: it is the unit you can
rotate.

### What leaves your network

Only the first **10 hex characters** of the SHA-256 of each password. The full
hash never leaves the machine — the match is done locally against the
candidates the API returns. Answers are cached by full hash, so a password
reused across 40 secrets costs one API call.

`revealedInExposure` is what separates the two match verdicts:

| Verdict | Meaning |
|---|---|
| `Compromised` | Matched, and `revealedInExposure` is true — the plaintext appeared in a breach |
| `Weak` | Matched, and `revealedInExposure` is false — known-weak, but never exposed |
| `Clean` | Checked against Enzoic, no match |
| `CheckFailed` | The lookup did not complete. **Not a pass** |

`CheckFailed` is counted separately in the summary for a reason: an
inconclusive check reported as a pass would quietly undermine the whole
exercise.

## The API, and the version trap

Verified against the 12.1.2 OpenAPI spec.

| Step | Endpoint |
|---|---|
| Token / refresh | `POST /oauth2/token` |
| Folder by name | `GET /api/v1/folders` — **v1** |
| Secrets in folder | `GET /api/v2/secrets?filter.folderId=` — **v2** |
| Read a secret | `GET /api/v2/secrets/{id}` — **v2**, `items[]` with `isPassword` |

**Search and get are v2; folders are v1.** `/api/v1/secrets` has no GET at all,
only POST (create). `GET /api/v1/secrets?filter.folderId=` is the obvious first
guess and it does not exist.

Reading via `items[].isPassword` means one call per secret gets the username and
the password without assuming the field slug is `password`. Items with `isFile`
set are ignored — an attached file is not a password.

## Things that cost real time

- **`expires_in` is a string** in the spec. Cast it.
- **`refresh_token` is not always issued** — only *"when the server is set to
  allow refresh tokens for web services and when the session timeout duration
  is not set to Unlimited."* Both integrations fall back to a password grant
  when it is absent, and when refreshing fails (an aged-out refresh token
  returns the same HTTP 400 as bad credentials).
- **`noAutoCheckout=true` on every read.** Without it, reading a
  checkout-required secret checks it out *under the API account* and locks it
  away from whoever needs it. Those secrets are skipped instead, and reported
  as skipped.
- **Secret Server cold-starts slowly.** After an IIS app pool recycle — which
  saving a permission change can trigger — the first request blows past a
  normal timeout and fails as a *read* timeout: the TCP connect succeeded, the
  app just did not answer. Both retry with backoff and say so.
- **Secret Server Cloud rate limits where on-prem does not.** A sweep is one
  request per secret, so a large cloud vault will be throttled. An HTTP 429 is
  caught and retried with backoff, honouring `Retry-After`; `ThrottleDelayMs` /
  `throttle_delay_ms` paces the whole sweep if the retries are still not enough.
- **Ambiguous folder names are an error, not a guess.** `filter.searchText` is
  a contains match and two folders can share a leaf name; pass a full path.
- **The OAuth token endpoint sits outside `/api`**, so it is not in the 12.1.2
  OpenAPI spec. The `domain` form field on the password grant comes from
  Delinea's docs rather than from the spec like everything else here.
