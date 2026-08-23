# Signing in with corporate SSO

Where a Fusion instance sits behind Okta, Entra or anything similar, there is
no password to put in a secret. This is the way round that.

## How it works

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    PROVIDER browser,
    ENDPOINT 'https://<your-fusion-host>',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo'
);

SELECT * FROM fusion_scanner_sso_login();
```

There is no separate sign-in URL to configure. The report endpoint and the
Fusion application share a host, and reaching that host unauthenticated is
precisely what triggers the sign-on redirect — so the scheme and host of
`ENDPOINT` are all the browser needs. `SSO_LOGIN_URL` exists only for instances
where that is not true: a separate vanity host, or a sign-in that has to start
at a particular page.

1. A browser is launched with a debugging port on loopback and pointed at your
   Fusion instance.
2. You sign in the way you normally do. The extension is not involved: whatever
   your organisation requires — a second factor, a smartcard, a conditional
   access policy — happens between you and your identity provider.
3. Once you are signed in, the extension asks the page to call
   `/fscmRestApi/anticsrf` and then `/fscmRestApi/tokenrelay`. Fusion hands its
   own signed-in session a bearer token, and that is what gets used.

There is no client secret, no registered OAuth application and no password
anywhere in this process. The anti-CSRF step is what stops any other site from
collecting a token the same way.

## What is stored, and where

| Thing | Where | Survives a restart |
|---|---|---|
| Bearer token | memory only | no |
| Browser session cookie | `~/.fusion_scanner/chrome-profile` | yes |
| Endpoint, report path, login URL | the secret | if `PERSISTENT` |

The token is never written to disk. Persistence comes from the browser profile
instead: the next sign-in is usually a click rather than a password, because
the cookie is still there.

`CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` **unencrypted** —
but a browser secret holds no credential to leak, only where to sign in.

## Two rules worth knowing

**A query never opens a browser.** If there is no token, the query fails and
tells you to run `fusion_scanner_sso_login()`. Sign-in is interactive and slow; an
ordinary `SELECT` becoming interactive would be a bad surprise in a script and
a worse one in a scheduled job.

**`CREATE SECRET` does not open a browser either**, so it is safe to run from a
setup script.

## Managing the session

```sql
SELECT * FROM fusion_scanner_sso_status();   -- signed in? as whom? until when?
SELECT * FROM fusion_scanner_sso_login(force := true);   -- sign in again now
SELECT * FROM fusion_scanner_sso_logout();   -- discard the token
```

`fusion_scanner_sso_status()` never prints the token itself. It is a live credential,
and printing it would put it into terminal scrollback and query history.

A token is treated as expired shortly before it really is, and is refreshed
once about 80% of its life has passed — so the refresh lands between queries
rather than in the middle of one.

## Using a token from elsewhere

On a machine with no browser — a server, a CI runner — obtain a token by
whatever means you already have and hand it over directly:

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    ENDPOINT '…', REPORT_PATH '…',
    AUTH 'bearer',
    TOKEN '<jwt>'
);
```

This is also the fallback when the browser flow cannot run at all.

## When it does not work

**No browser found.** Chrome, Chromium or Edge is required. Point at it with
`OFQUACK_CHROME_PATH` or `CHROME_PATH` on the secret.

**The window opens and nothing happens.** The token is only issued once Fusion
considers you signed in — reaching the application, not just the login page.
Raise `SSO_TIMEOUT_SECONDS` if your sign-in is slow.

**A second window appears asking you to sign in again.** Chrome hands a URL to
an instance already running under the same profile and exits, which looks to
this code like a failure to start; it retries with a throwaway profile, which
carries no cookies. Closing the other Chrome window first avoids it.

**`Not signed in to <host>`** on a query means exactly that — run
`fusion_scanner_sso_login()`.

## What is not verified

The JWT's signature is not checked, deliberately. Fusion authenticates the
token when it is used; the extension reads only the expiry, to know when to ask
for another. A token this code received from a browser it launched itself is not
a token it needs to police.

---

See also: [the function reference](REFERENCE.md) for every function and
setting, and the [README](../README.md) to start from the beginning.
