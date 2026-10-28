# Ladylain.MicrosoftLogin

*[Version française](README.fr.md)*

Adds a **"Sign in with Microsoft"** button to the October CMS (v4) backend sign-in page,
for your organization's Microsoft 365 accounts (Entra ID).

- OpenID Connect, *authorization code + PKCE* flow, single tenant.
- Only **existing backend accounts** can sign in: no account is ever created.
- Password sign-in remains available.
- The application authenticates with a **client secret** or a **certificate**
  (the same certificate as Ladylain.Office365Mailer works).

## Installation

```bash
php artisan plugin:install Ladylain.MicrosoftLogin --from=https://github.com/Ladylain/oc-microsoft-login.git --oc --want=dev-main
```

Updates: `php artisan october:update` (or `composer update ladylain/oc-microsoftlogin-plugin`).

Requires PHP 8.2+ and `firebase/php-jwt` ^6.11 (`composer require firebase/php-jwt` if it is not already installed).

## Configuration (Settings → Administrators → Microsoft Login)

1. **Entra ID → App registrations**: create a *single tenant* application, or reuse an existing one.
2. **Authentication → Add a platform → Web**: add the redirect URI shown in the settings,
   `https://<site>/<backend>/ladylain/microsoftlogin/sso/callback`.
   The platform must be **Web**, not "Single-page application" (otherwise error AADSTS9002327).
3. **Certificates & secrets**: create a secret (copy its *Value*) or upload the public certificate.
4. Fill in the tenant ID, application ID and secret or certificate paths, save,
   then click **Test saved configuration**.
5. Enable the login.

Signing in requires no Graph permission: only the `openid profile email` claims are requested.

## Automated setup for a new site

**Once per application** (by an Entra ID administrator):

1. Microsoft Graph application permission **Application.ReadWrite.OwnedBy**, with admin consent.
2. Make the application its own owner, for example in Graph Explorer:
   - `GET https://graph.microsoft.com/v1.0/servicePrincipals(appId='<client_id>')?$select=id` → `SP_ID`
   - `POST https://graph.microsoft.com/v1.0/applications(appId='<client_id>')/owners/$ref`
     with the body `{ "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/SP_ID" }`

Then, on each site:

```bash
php artisan october:migrate
php artisan microsoftlogin:register --import-mailer --enable
```

- `--import-mailer` copies the tenant, application and certificate from Ladylain.Office365Mailer, if installed.
- The URI is built from `APP_URL` and `BACKEND_URI`: check them in `.env`. Entra ID only accepts https.
- The command adds the site's redirect URI to the application and never removes any. Running it again does nothing.
- `--enable` only enables the button once the URI has been registered.

The **Use Office365Mailer configuration** and **Register this site in Azure** buttons on the settings page do the same.

Warning: the `Application.ReadWrite.OwnedBy` permission lets the application modify its own registration,
including its secrets. Protect the certificate accordingly, or remove the permission between installations.

## Account matching

| Situation | Result |
|---|---|
| Microsoft account already linked (tenant + `oid`) | signed in, even if the email changed |
| First sign-in, one backend account has the same address (`email`, `preferred_username` or `upn`, case-insensitive) | linked, then signed in |
| No matching account | refused, with a message giving the address to create |
| Several matching accounts | refused |
| Backend account already linked to another Microsoft account | refused (protects against reassigned addresses) |
| Account not activated, suspended, banned or deleted | refused |

Links are stored in `ladylain_microsoftlogin_identities`, with a foreign key to `backend_users`
and cascading deletes. To unlink an account, delete its row.

## Security

- `state` (CSRF), `nonce` (replay) and PKCE verifier kept in the session, single use, valid for 10 minutes.
- ID token checked: RS256 signature against the tenant keys (reloaded once on key rotation),
  exact tenant issuer, audience = application ID, expiry (2 min leeway), `tid`, `nonce`.
  The `none` and HS256 algorithms are rejected.
- The `common`, `organizations` and `consumers` tenants are rejected in the settings.
- The client secret is encrypted in the database (`APP_KEY`), never displayed again, logged or sent to the browser.
- Same safeguards as password sign-in: activation, suspension and bans, access log (`AccessLog`).
- Laravel log: sign-ins and refusals (`[MicrosoftLogin]`), with the AADSTS code but never a token.

## Tests

```bash
php artisan plugin:test Ladylain.MicrosoftLogin
```

Entra ID is simulated with a real RSA key pair: tokens are actually signed, then verified.

## License

[MIT](LICENSE) — free to use, modify and distribute.
