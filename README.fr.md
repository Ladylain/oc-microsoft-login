# Ladylain.MicrosoftLogin

*[English version](README.md)*

Bouton **« Se connecter avec Microsoft »** sur la page de connexion du back-office October CMS (v4),
avec les comptes Microsoft 365 de l'entreprise (Entra ID).

- OpenID Connect, flux *code d'autorisation + PKCE*, tenant unique.
- Seuls les **comptes back-office existants** peuvent se connecter : aucun compte n'est créé.
- La connexion par mot de passe reste disponible.
- Application authentifiée par **secret client** ou **certificat** (le même que Ladylain.Office365Mailer convient).

## Installation

```bash
php artisan plugin:install Ladylain.MicrosoftLogin --from=https://github.com/Ladylain/oc-microsoft-login.git --oc --want=dev-main
```

Mises à jour : `php artisan october:update` (ou `composer update ladylain/oc-microsoftlogin-plugin`).

PHP 8.2+ et `firebase/php-jwt` ^6.11 (déjà présente si Office365Mailer est installé, sinon `composer require firebase/php-jwt`).

## Configuration (Réglages → Administrateurs → Connexion Microsoft)

1. **Entra ID → Inscriptions d'applications** : créer une application *locataire unique*, ou réutiliser celle d'Office365Mailer.
2. **Authentification → Ajouter une plateforme → Web** : ajouter l'URI de redirection affichée dans les réglages,
   `https://<site>/<backend>/ladylain/microsoftlogin/sso/callback`.
   La plateforme doit être **Web**, pas « Application monopage » (sinon erreur AADSTS9002327).
3. **Certificats et secrets** : créer un secret (copier sa *Valeur*) ou téléverser le certificat public.
4. Renseigner l'ID du locataire, l'ID d'application et le secret ou les chemins du certificat, enregistrer,
   puis cliquer sur **Tester la configuration enregistrée**.
5. Activer la connexion.

La connexion elle-même ne demande aucune permission Graph : seules les revendications `openid profile email` sont demandées.

## Installation automatisée d'un nouveau site

Préparation, **une seule fois** pour l'application (par un administrateur Entra ID) :

1. Permission d'application Microsoft Graph **Application.ReadWrite.OwnedBy**, avec consentement administrateur.
2. Rendre l'application propriétaire d'elle-même, par exemple dans Graph Explorer :
   - `GET https://graph.microsoft.com/v1.0/servicePrincipals(appId='<client_id>')?$select=id` → `SP_ID`
   - `POST https://graph.microsoft.com/v1.0/applications(appId='<client_id>')/owners/$ref`
     avec le corps `{ "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/SP_ID" }`

Ensuite, sur chaque site :

```bash
php artisan october:migrate
php artisan microsoftlogin:register --import-mailer --enable
```

- `--import-mailer` reprend tenant, application et certificat d'Office365Mailer.
- L'URI vient de `APP_URL` et de `BACKEND_URI` : vérifiez-les dans `.env`. Entra ID n'accepte que le https.
- La commande ajoute l'URI de redirection du site à l'application et n'en retire aucune. Relancée, elle ne fait rien.
- `--enable` n'active le bouton que si l'URI a bien été déclarée.

Les boutons « Reprendre la configuration d'Office365Mailer » et « Déclarer ce site dans Azure » de la page de réglages font la même chose.

Attention, la permission `Application.ReadWrite.OwnedBy` permet à l'application de modifier sa propre inscription,
y compris ses secrets. Protégez le certificat en conséquence, ou retirez la permission entre deux installations.

## Association des comptes

| Situation | Résultat |
|---|---|
| Compte Microsoft déjà lié (tenant + `oid`) | connexion, même si l'e-mail a changé |
| Première connexion, un compte back-office a la même adresse (`email`, `preferred_username` ou `upn`, sans tenir compte de la casse) | liaison puis connexion |
| Aucun compte correspondant | refus, avec un message qui donne l'adresse à créer |
| Plusieurs comptes correspondants | refus |
| Compte back-office déjà lié à un autre compte Microsoft | refus (protège contre une adresse réattribuée) |
| Compte non activé, suspendu ou banni, ou supprimé | refus |

La liaison est stockée dans `ladylain_microsoftlogin_identities`, avec une clé étrangère vers `backend_users`
et une suppression en cascade. Pour délier un compte, supprimer sa ligne.

## Sécurité

- `state` (anti-CSRF), `nonce` (anti-rejeu) et vérificateur PKCE en session, à usage unique, valables 10 minutes.
- Jeton d'identité vérifié : signature RS256 avec les clés du tenant (rechargées une fois en cas de rotation),
  émetteur exact du tenant, audience = ID d'application, expiration (tolérance 2 min), `tid`, `nonce`.
  Les algorithmes `none` et HS256 sont refusés.
- Les tenants `common`, `organizations` et `consumers` sont refusés dans les réglages.
- Le secret client est chiffré en base (`APP_KEY`), n'est jamais réaffiché, journalisé ni envoyé au navigateur.
- Mêmes garde-fous que la connexion par mot de passe : activation, suspension et bannissement, journal d'accès (`AccessLog`).
- Journal Laravel : connexions et refus (`[MicrosoftLogin]`), avec le code AADSTS mais jamais de jeton.

## Tests

```bash
php artisan plugin:test Ladylain.MicrosoftLogin
```

Entra ID est simulé avec une vraie paire de clés RSA : les jetons sont réellement signés puis vérifiés.

## Licence

[MIT](LICENSE) : utilisation, modification et redistribution libres.
