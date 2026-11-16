# @mmlabs/auth-client

Browser client for **mmlabs Identity** (`https://api.mmlabs.online`): sign-up, sign-in, account
choice per origin, per-app access tokens kept in memory, Bearer calls to your own backend, join,
logout, email verification and password reset. Plus a React wrapper at `@mmlabs/auth-client/react`.

API contract: [`org-admin-api/docs/consumers.md`](https://github.com/mmlabs-online/org-admin-api/blob/main/docs/consumers.md).
If this library and that page disagree, the page wins and the library gets a fix.

## 1. Install

The package is not on a registry (`"private": true` only blocks an accidental `npm publish`). Each
release is a tarball on a GitHub Release tagged `ts-vX.Y.Z`. The repository is public, so no
GitHub token is needed.

Recommended: vendor the tarball into your repo, so builds (Docker included) never reach GitHub.

```bash
V=0.1.0
mkdir -p vendor
curl -fsSLo vendor/mmlabs-auth-client-$V.tgz \
  https://github.com/mmlabs-online/mmlabs-auth/releases/download/ts-v$V/mmlabs-auth-client-$V.tgz
sha256sum vendor/mmlabs-auth-client-$V.tgz   # compare with the SHA-256 in the release notes
pnpm add ./vendor/mmlabs-auth-client-$V.tgz  # → "@mmlabs/auth-client": "file:vendor/…tgz"
```

The package has no runtime dependencies and no install scripts. `react >= 18` is an optional peer,
needed only for `@mmlabs/auth-client/react`. It ships ES modules with type declarations.

## 2. Create the client

Create **one client per page**, at module level, and reuse it.

```ts
import { createAuthClient } from "@mmlabs/auth-client";

export const auth = createAuthClient({
  baseUrl: "https://api.mmlabs.online",
  appKey: "ricotdin",
  apiOrigins: ["https://ricotdin.mmlabs.online"],
});
```

| Option                   | Default             | Meaning                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `baseUrl`                | required            | Identity API origin. Must be `https:` (no userinfo, query or fragment).                                                                                                                                                                                                                                                                                        |
| `appKey`                 | required            | Your app's key (`^[a-z][a-z0-9-]{1,31}$`). Sent as `X-MM-App` and used as the token audience.                                                                                                                                                                                                                                                                  |
| `apiOrigins`             | `[location.origin]` | Origins `fetchWithToken` may send the Bearer token to: `https:`, or loopback `http:` with `allowInsecureLocalhost`. List your backend's origin when it is not the page origin. Without `location` (SSR, Node) and without this option, `fetchWithToken` throws `bearer_origin_not_allowed`. The identity API's `/api/v1/auth/*` never receives a Bearer token. |
| `storage`                | `localStorage`      | Where `mm_account_id` lives. `null` keeps it in memory only. A throwing storage falls back to memory.                                                                                                                                                                                                                                                          |
| `broadcast`              | `true`              | Cross-tab sync through `BroadcastChannel("mmlabs-auth:<appKey>")`, with the `storage` event as a fallback. `false` turns both off. A factory may be passed for tests.                                                                                                                                                                                          |
| `allowInsecureLocalhost` | `false`             | Allows `http://localhost`, `127.0.0.1` and `[::1]` for `baseUrl` and `apiOrigins`. Local development only.                                                                                                                                                                                                                                                     |
| `fetch`, `now`           | globals             | Injection points for tests.                                                                                                                                                                                                                                                                                                                                    |

Invalid options (and other programmer errors, such as a non-UUID `accountId`) throw `TypeError`
synchronously and send nothing.

## 3. Methods

| Method                                                    | Endpoint                                | Request class | Returns                                                       |
| --------------------------------------------------------- | --------------------------------------- | ------------- | ------------------------------------------------------------- |
| `signup({email, password, turnstileToken})`               | `POST /api/v1/auth/signup`              | cookie        | `SignupResult`                                                |
| `login({email, password, turnstileToken?})`               | `POST /api/v1/auth/login`               | cookie        | `LoginResult`; selects the account                            |
| `listAccounts()`                                          | `GET /api/v1/auth/accounts`             | cookie        | `Account[]` (every account signed in on this device)          |
| `getAccountId()` / `selectAccount(id)` / `clearAccount()` | — (local)                               | —             | This origin's `mm_account_id`                                 |
| `getToken(options?)`                                      | `POST /api/v1/auth/token`               | cookie        | Access token string (memory cache)                            |
| `fetchWithToken(input, init?)`                            | your backend                            | Bearer        | `Response`                                                    |
| `join(accountId)`                                         | `POST /api/v1/auth/apps/<appKey>/join`  | cookie        | `"member"`                                                    |
| `logout({accountId})` / `logout({all: true})`             | `POST /api/v1/auth/logout`              | cookie        | —                                                             |
| `resendVerification(accountId?)`                          | `POST /api/v1/auth/verify-email/resend` | cookie        | `"sent"` or `"already_verified"`                              |
| `forgotPassword({email, turnstileToken})`                 | `POST /api/v1/auth/password/forgot`     | cookie        | — (202 for every email)                                       |
| `verifyEmail(token)`                                      | `POST /api/v1/auth/verify-email`        | public        | —                                                             |
| `resetPassword({token, newPassword})`                     | `POST /api/v1/auth/password/reset`      | public        | —                                                             |
| `invalidateToken()`                                       | — (local)                               | —             | Drops cached tokens (e.g. after a role change)                |
| `onChange(listener)`                                      | —                                       | —             | Unsubscribe function. Events: `account-changed`, `signed-out` |
| `dispose()`                                               | —                                       | —             | Closes the channel, removes listeners, drops tokens           |

**Credentials rules (fixed, not configurable):**

- **cookie** requests go only to `/api/v1/auth/*` on `baseUrl`, with `credentials: "include"`,
  `X-MM-App: <appKey>` and `cache: "no-store"`. `Content-Type` is set only with a body.
- **public** requests (`verifyEmail`, `resetPassword`) use `credentials: "omit"` and no `X-MM-App`.
- **Bearer** requests (`fetchWithToken`) always use `credentials: "omit"`, strip any `X-MM-App`,
  and set `Authorization: Bearer <token>`, even when the caller passes other values.

## 4. Sign-in and account choice

A browser holds one device session with any number of signed-in accounts. Each app (origin)
remembers its own choice in `localStorage` as `mm_account_id` (a UUID, nothing else is stored).

```ts
const accounts = await auth.listAccounts(); // SessionInvalidError → nobody is signed in
const chosen = auth.getAccountId();
if (accounts.length === 0) showLogin();
else if (!accounts.some((a) => a.accountId === chosen))
  showAccountPicker(accounts); // "Continue as …"
else showApp();

// Login form (Turnstile token when the API asks for one: TurnstileRequiredError)
await auth.login({ email, password, turnstileToken }); // also selects the account
// Account picker
auth.selectAccount(account.accountId); // drops cached tokens
// Logout
await auth.logout({ accountId: auth.getAccountId()! }); // or { all: true }
```

`logout` clears local state (tokens, and `mm_account_id` when it matches) and tells other tabs
**before** the request, so a failed request still leaves this browser signed out locally.

### Tokens

```ts
const token = await auth.getToken(); // audience = appKey
const res = await auth.fetchWithToken("/api/notes"); // relative to location, or an apiOrigins URL
```

- Tokens live in memory only, keyed by account and audience. A token is reused until
  `expires_in − min(60 s, 20 %)`; the next call after that fetches a new one. There are no timers.
- Concurrent calls share one request. Failures are not cached.
- `getToken("other-app")` rejects with `ConfigurationError("audience_mismatch")`: an app only gets
  tokens for itself.
- If the account changes (switch, logout, another tab) while a token request is in flight, the
  request rejects with `AuthError("account_changed")` and its token is dropped. Re-read the state
  and call again.
- On a 401 from your backend, `fetchWithToken` refreshes the token once and retries once (at most
  once per 30 s), then returns that second `Response` whatever its status.
- After a `429 rate_limited` on `/token`, calls reject locally with `RateLimitedError` until
  `retryAfter` seconds pass. Nothing retries automatically.

### Join: `not_member` → explicit "Continue as"

```ts
try {
  await auth.getToken();
} catch (e) {
  if (e instanceof NotMemberError && e.joinAvailable) {
    showContinueAs(account); // on the user's click only:
    // await auth.join(account.accountId); await auth.getToken();
  }
}
```

**Never join automatically.** The user's click on "Continue as <email>" is the consent (D8). The
library never calls `join` itself, and `join` requires an explicit `accountId`.
`JoinUnavailableError` (`join_closed`, `join_approval_unavailable`, `join_unavailable`) means the
app does not accept this join.

## 5. Email verification and password reset

`EmailUnverifiedError` (from `getToken` or `join`): a verified email is required for any app
token.

```ts
const r = await auth.resendVerification(); // "sent" | "already_verified"
// … the user clicks the link in the email (in any tab) …
await auth.getToken({ forceRefresh: true }); // fetches a fresh token now
```

Every registered origin of your app must serve `/verify-email` and `/reset-password`. The token is
in the URL fragment (`#token=…`), so it never reaches a server log. On those pages:

1. read `location.hash`, then remove it at once: `history.replaceState(null, "", "/verify-email")`;
2. serve the page with `Referrer-Policy: no-referrer`;
3. call `auth.verifyEmail(token)` or `auth.resetPassword({ token, newPassword })` (public requests,
   no cookies). `TokenInvalidError` means the link is used, expired or replaced.

## 6. Errors

Every error is an `AuthError` with `code`, `status`, `requestId` (from `X-Request-ID`) and a fixed
message `mmlabs-auth: <code>`. Server messages, request bodies, emails and tokens are never kept.
Use `instanceof`:

| Class                                             | Codes                                                                                                                                          | What to do                                                                                                                                               |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SessionInvalidError`                             | `session_invalid`                                                                                                                              | Account not signed in on this device: re-list accounts or show login. Cached tokens for that account are dropped; `mm_account_id` stays.                 |
| `InvalidCredentialsError`                         | `invalid_credentials`                                                                                                                          | Same answer for unknown email and wrong password.                                                                                                        |
| `NotMemberError` (`joinAvailable`)                | `not_member`                                                                                                                                   | Show "Continue as" when `joinAvailable`; otherwise no access.                                                                                            |
| `EmailUnverifiedError`                            | `email_unverified`                                                                                                                             | Resend verification, then `getToken({forceRefresh: true})`.                                                                                              |
| `TurnstileRequiredError` / `TurnstileFailedError` | `turnstile_required`, `turnstile_failed`                                                                                                       | Show or re-run the Turnstile challenge.                                                                                                                  |
| `JoinUnavailableError`                            | `join_closed`, `join_approval_unavailable`, `join_unavailable`                                                                                 | The app does not accept this join.                                                                                                                       |
| `RateLimitedError` (`retryAfter` s)               | `rate_limited`                                                                                                                                 | Wait `retryAfter` seconds (from `Retry-After`, capped at 900).                                                                                           |
| `EmailTakenError`                                 | `email_taken`                                                                                                                                  | Sign-up: offer login instead.                                                                                                                            |
| `EmailAlreadyVerifiedError`                       | `email_already_verified`                                                                                                                       | `resendVerification` turns it into `"already_verified"`.                                                                                                 |
| `WeakPasswordError` (`reasons`)                   | `weak_password`                                                                                                                                | Show the reasons.                                                                                                                                        |
| `ValidationError` (`issues: {type, loc}[]`)       | `validation_error`                                                                                                                             | Bug or bad input.                                                                                                                                        |
| `TokenInvalidError`                               | `token_invalid`                                                                                                                                | Verify/reset link is no longer valid.                                                                                                                    |
| `ConfigurationError`                              | `audience_mismatch`, `app_header_required`, `origin_not_allowed`, `app_mismatch`, `org_not_supported`, **`bearer_origin_not_allowed`** (local) | Misconfiguration. `bearer_origin_not_allowed`: the `fetchWithToken` target is not https, not in `apiOrigins`, or is the identity API's `/api/v1/auth/*`. |
| `NetworkError`                                    | `network_error` (local)                                                                                                                        | Request did not complete (offline, CORS refusal).                                                                                                        |
| `AuthError`                                       | `account_changed` (local)                                                                                                                      | The account changed while a token request was in flight. Call again for the current account.                                                             |
| `AuthError`                                       | `no_account_selected` (local)                                                                                                                  | Call `selectAccount` or `login` first.                                                                                                                   |
| `AuthError`                                       | `unexpected_response`, any other code                                                                                                          | Generic fallback; `code` holds the server code.                                                                                                          |

Local codes have `status: 0` (except `unexpected_response`, which keeps the HTTP status). The full
list is in [`contract/error-codes.json`](../contract/error-codes.json).

## 7. React

```tsx
import { createAuthClient, NotMemberError } from "@mmlabs/auth-client";
import { AuthProvider, useAccessToken, useAuth, useJoin } from "@mmlabs/auth-client/react";
```

- `<AuthProvider client={auth}>` lists the accounts on mount and after every client event (login,
  account choice, logout, other tabs).
- `useAuth()` → `{status, accounts, accountId, error, selectAccount, login, logout, reload}`.
  `status` is `"loading"`, `"signed-out"` (no accounts or `session_invalid`), `"needs-account"`
  (accounts exist, none chosen for this app), `"ready"` or `"error"` (`error` set). `accountId` is
  set only when `"ready"`.
- `useAccessToken()` → `{getToken, fetchWithToken}`: stable functions. **There is no token value**
  in React state, context or props, by design. Call `getToken()` where you need it, do not put the
  result in state.
- `useJoin()` → `{join(accountId), pending, error}`. `join` rethrows on failure.
- Hooks used outside `<AuthProvider>` throw.

Example for `admin-pan` (`appKey: "admin"`, Bearer calls to the admin API):

```tsx
const auth = createAuthClient({
  baseUrl: "https://api.mmlabs.online",
  appKey: "admin",
  apiOrigins: ["https://api.mmlabs.online"], // admin endpoints; /api/v1/auth/* is always refused
});

export function Root() {
  return (
    <AuthProvider client={auth}>
      <Gate />
    </AuthProvider>
  );
}

function Gate() {
  const { status, accounts, selectAccount } = useAuth();
  if (status === "loading") return <Spinner />;
  if (status === "signed-out") return <LoginForm />; // uses useAuth().login
  if (status === "needs-account")
    return <AccountPicker accounts={accounts} onPick={selectAccount} />;
  if (status === "error") return <Retry />; // useAuth().reload
  return <Organizations />;
}

function Organizations() {
  const { fetchWithToken } = useAccessToken();
  useEffect(() => {
    fetchWithToken("https://api.mmlabs.online/api/v1/organizations?limit=50")
      .then((r) => r.json())
      .then(setPage)
      .catch((e) => (e instanceof NotMemberError ? showNoAccess() : showError(e)));
  }, [fetchWithToken]);
  // …
}
```

The `admin` app cannot host sign-up, forgot-password or resend-verification: the API answers 403
for those (ADM-002d). Link to another mmlabs app for them. `admin` does not accept joins either
(`join_closed`): admin access is granted by staff.

## 8. Security notes

- **Tokens stay in memory only.** The client keeps them in private fields; it never writes them to
  `localStorage`, `sessionStorage`, IndexedDB, cookies, URLs, globals, React state or logs. Do not
  do it yourself either: call `getToken()` / `fetchWithToken()` each time.
- The only value the library writes to storage is `mm_account_id` (a UUID). Cross-tab messages carry
  no token or email.
- The library makes no `console.*` calls, and its errors contain no secrets.
- **The library cannot defeat XSS.** Script running on your origin can call `getToken()` and act as
  the user in your app (for `admin-pan`: a full admin compromise). The control is a strict CSP.
  Recommended starting point (add the Turnstile hosts only on pages that show the challenge):

  ```
  Content-Security-Policy: default-src 'self'; script-src 'self' https://challenges.cloudflare.com;
    frame-src https://challenges.cloudflare.com; connect-src 'self' https://api.mmlabs.online;
    object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';
    require-trusted-types-for 'script'
  ```

  No `'unsafe-inline'` or `'unsafe-eval'` in `script-src`. Enable Trusted Types where your framework
  supports it. Keep third-party scripts off pages that use the client.
- **Revocation lag:** an access token stays valid until it expires (up to 15 min) after logout or a
  role change. Backends that need faster revocation must check elsewhere.
- Use `allowInsecureLocalhost` only in development builds.
