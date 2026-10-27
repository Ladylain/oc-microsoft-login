<?php namespace Ladylain\MicrosoftLogin\Classes;

use Cache;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\ConnectionException;
use Ladylain\MicrosoftLogin\Models\Settings;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;
use Throwable;

/**
 * OidcClient parle à Microsoft Entra ID (OpenID Connect v2, tenant unique).
 *
 * Flux : code d'autorisation + PKCE, échange du code côté serveur, validation complète
 * du jeton d'identité (signature JWKS, émetteur, audience, expiration, nonce).
 */
class OidcClient
{
    const AUTHORITY = 'https://login.microsoftonline.com';

    const SCOPES = 'openid profile email';

    const HTTP_TIMEOUT = 10;

    const LEEWAY = 120;

    public function __construct(protected Settings $settings)
    {
    }

    /**
     * authorizationUrl vers laquelle rediriger le navigateur.
     */
    public function authorizationUrl(string $state, string $nonce, string $codeVerifier, string $redirectUri): string
    {
        return $this->discovery()['authorization_endpoint'] . '?' . http_build_query([
            'client_id' => $this->settings->client_id,
            'response_type' => 'code',
            'response_mode' => 'query',
            'redirect_uri' => $redirectUri,
            'scope' => self::SCOPES,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => static::codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
            'prompt' => 'select_account',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * exchangeCode échange le code contre un jeton d'identité et renvoie ses revendications validées.
     */
    public function exchangeCode(string $code, string $codeVerifier, string $redirectUri, string $nonce): array
    {
        $response = $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
            'scope' => self::SCOPES,
        ]);

        if (empty($response['id_token']) || !is_string($response['id_token'])) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.no_id_token'));
        }

        return $this->validateIdToken($response['id_token'], $nonce);
    }

    /**
     * testCredentials vérifie le tenant, l'application et le secret/certificat
     * en demandant un jeton applicatif (flux client credentials), sans utilisateur.
     */
    public function testCredentials(): void
    {
        $this->graphToken();
    }

    /**
     * graphToken : jeton applicatif Microsoft Graph (permissions accordées à l'application).
     */
    public function graphToken(): string
    {
        $response = $this->tokenRequest([
            'grant_type' => 'client_credentials',
            'scope' => 'https://graph.microsoft.com/.default',
        ]);

        if (empty($response['access_token']) || !is_string($response['access_token'])) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.generic', ['code' => 'no_access_token']));
        }

        return $response['access_token'];
    }

    /**
     * validateIdToken contrôle signature et revendications ; renvoie les revendications.
     */
    public function validateIdToken(string $idToken, string $nonce): array
    {
        $claims = $this->decodeIdToken($idToken);
        $issuer = $this->discovery()['issuer'];

        if (($claims['iss'] ?? null) !== $issuer) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.invalid_token'), 'iss inattendu');
        }

        $aud = (array) ($claims['aud'] ?? []);
        if (!in_array($this->settings->client_id, $aud, true)) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.invalid_token'), 'aud inattendu');
        }

        if (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.invalid_token'), 'nonce invalide');
        }

        // L'émetteur du tenant contient son GUID : le tid du jeton doit y correspondre
        if (empty($claims['tid']) || !str_contains($issuer, '/' . $claims['tid'] . '/')) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.wrong_tenant'), 'tid inattendu');
        }

        if (empty($claims['oid'])) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.invalid_token'), 'oid absent');
        }

        return $claims;
    }

    /**
     * decodeIdToken vérifie la signature avec les clés publiques du tenant (RS256 uniquement).
     * Si la clé est inconnue (rotation chez Microsoft), les clés sont rechargées une fois.
     */
    protected function decodeIdToken(string $idToken): array
    {
        JWT::$leeway = self::LEEWAY;

        foreach ([false, true] as $refresh) {
            try {
                return (array) JWT::decode($idToken, JWK::parseKeySet($this->jwks($refresh), 'RS256'));
            }
            catch (SsoException $ex) {
                throw $ex;
            }
            catch (Throwable $ex) {
                $error = $ex;
            }
        }

        throw new SsoException(__('ladylain.microsoftlogin::lang.errors.invalid_token'), $error->getMessage());
    }

    /**
     * discovery : document OpenID du tenant, mis en cache 24 h.
     */
    public function discovery(): array
    {
        $tenant = $this->settings->tenant_id;

        return Cache::remember('ladylain.microsoftlogin.discovery.' . md5($tenant), 86400, function () use ($tenant) {
            $doc = $this->getJson(self::AUTHORITY . '/' . rawurlencode($tenant) . '/v2.0/.well-known/openid-configuration');

            foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $key) {
                if (empty($doc[$key]) || !str_starts_with($doc[$key], 'https://')) {
                    throw new SsoException(__('ladylain.microsoftlogin::lang.errors.discovery'), "clé $key absente");
                }
            }

            return $doc;
        });
    }

    protected function jwks(bool $refresh = false): array
    {
        $key = 'ladylain.microsoftlogin.jwks.' . md5($this->settings->tenant_id);

        if ($refresh) {
            Cache::forget($key);
        }

        return Cache::remember($key, 86400, fn () => $this->getJson($this->discovery()['jwks_uri']));
    }

    protected function getJson(string $url): array
    {
        try {
            $response = Http::timeout(self::HTTP_TIMEOUT)->acceptJson()->get($url);
        }
        catch (ConnectionException $ex) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.unreachable'), $ex->getMessage());
        }

        if (!$response->successful()) {
            throw $this->microsoftError($response->json() ?? []);
        }

        return $response->json() ?? [];
    }

    /**
     * tokenRequest appelle le point de terminaison de jeton avec l'authentification du client.
     */
    protected function tokenRequest(array $params): array
    {
        $endpoint = $this->discovery()['token_endpoint'];
        $params = ['client_id' => $this->settings->client_id] + $params + $this->clientAuthentication($endpoint);

        try {
            $response = Http::timeout(self::HTTP_TIMEOUT)->acceptJson()->asForm()->post($endpoint, $params);
        }
        catch (ConnectionException $ex) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.unreachable'), $ex->getMessage());
        }

        if (!$response->successful()) {
            throw $this->microsoftError($response->json() ?? []);
        }

        return $response->json() ?? [];
    }

    protected function clientAuthentication(string $tokenEndpoint): array
    {
        if ($this->settings->auth_method !== 'certificate') {
            return ['client_secret' => (string) $this->settings->client_secret];
        }

        return [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion($tokenEndpoint),
        ];
    }

    /**
     * clientAssertion signe un JWT avec la clé privée du certificat (même principe qu'Office365Mailer).
     */
    protected function clientAssertion(string $tokenEndpoint): string
    {
        $keyPath = Settings::resolvePath((string) $this->settings->cert_path);
        $certPath = Settings::resolvePath((string) $this->settings->cert_pub_path);

        $privateKey = is_readable($keyPath) ? file_get_contents($keyPath) : false;
        $certificate = is_readable($certPath) ? file_get_contents($certPath) : false;

        if ($privateKey === false || $certificate === false) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.certificate_missing'));
        }

        $x509 = @openssl_x509_read($certificate);
        $thumbprint = $x509 ? openssl_x509_fingerprint($x509, 'sha1', true) : false;
        if ($thumbprint === false) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.certificate_invalid'));
        }

        $now = time();

        try {
            return JWT::encode([
                'aud' => $tokenEndpoint,
                'iss' => $this->settings->client_id,
                'sub' => $this->settings->client_id,
                'jti' => (string) Str::uuid(),
                'nbf' => $now,
                'iat' => $now,
                'exp' => $now + 600,
            ], $privateKey, 'RS256', null, ['x5t' => static::base64Url($thumbprint)]);
        }
        catch (Throwable $ex) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.certificate_invalid'), $ex->getMessage());
        }
    }

    /**
     * microsoftError traduit une réponse d'erreur Microsoft en message compréhensible.
     */
    public function microsoftError(array $body): SsoException
    {
        $error = (string) ($body['error'] ?? 'unknown_error');
        $description = (string) ($body['error_description'] ?? '');

        return static::errorFromCode($error, $description);
    }

    public static function errorFromCode(string $error, string $description = ''): SsoException
    {
        $code = preg_match('/AADSTS(\d+)/', $description, $m) ? $m[1] : null;
        $key = 'ladylain.microsoftlogin::lang.aadsts.' . ($code ?? $error);
        $message = __($key);

        if ($message === $key) {
            $message = __('ladylain.microsoftlogin::lang.errors.generic', ['code' => $code ? "AADSTS$code" : $error]);
        }

        // La description Microsoft ne contient pas de secret mais peut être longue : on garde la 1re ligne
        return new SsoException($message, trim($error . ' ' . strtok($description, "\r\n")));
    }

    public static function generateVerifier(): string
    {
        return static::base64Url(random_bytes(32));
    }

    public static function codeChallenge(string $verifier): string
    {
        return static::base64Url(hash('sha256', $verifier, true));
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
