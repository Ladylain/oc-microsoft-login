<?php namespace Ladylain\MicrosoftLogin\Tests;

use Cache;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use Ladylain\MicrosoftLogin\Models\Settings;

/**
 * FakeMicrosoft simule Entra ID (découverte, JWKS, jetons) avec une vraie paire de clés RSA :
 * les jetons sont réellement signés puis vérifiés par le plugin.
 */
trait FakeMicrosoft
{
    protected string $tenant = '11111111-2222-3333-4444-555555555555';

    protected string $clientId = '66666666-7777-8888-9999-000000000000';

    protected $rsaKey;

    protected string $kid = 'test-key-1';

    protected array $tokenRequests = [];

    protected array $tokenResponse = [];

    /** Inscription simulée de l'application dans Entra ID (propriété « web » de Graph) */
    protected array $graphWeb = [
        'homePageUrl' => 'https://www.example.com',
        'logoutUrl' => null,
        'redirectUris' => ['https://other-site.example.com/admin/ladylain/microsoftlogin/sso/callback'],
        'implicitGrantSettings' => ['enableAccessTokenIssuance' => false, 'enableIdTokenIssuance' => false],
        'redirectUriSettings' => [['uri' => 'https://other-site.example.com/admin/ladylain/microsoftlogin/sso/callback', 'index' => null]],
    ];

    protected int $graphStatus = 200;

    protected array $graphPatches = [];

    protected function configureSettings(array $overrides = []): Settings
    {
        Cache::flush();
        Settings::clearInternalCache();

        $settings = Settings::instance();
        $settings->forceFill(array_merge([
            'enabled' => true,
            'tenant_id' => $this->tenant,
            'client_id' => $this->clientId,
            'auth_method' => 'secret',
            'client_secret' => 'Sup3r~Secret.Value',
        ], $overrides));
        $settings->save();

        return $settings;
    }

    protected function issuer(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/v2.0";
    }

    protected function fakeMicrosoft(): void
    {
        $this->rsaKey ??= openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        Http::fake(function ($request) {
            $url = $request->url();

            if (str_contains($url, '/.well-known/openid-configuration')) {
                return Http::response([
                    'issuer' => $this->issuer(),
                    'authorization_endpoint' => "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/authorize",
                    'token_endpoint' => "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/token",
                    'jwks_uri' => "https://login.microsoftonline.com/{$this->tenant}/discovery/v2.0/keys",
                ]);
            }

            if (str_contains($url, '/discovery/v2.0/keys')) {
                return Http::response(['keys' => [$this->publicJwk()]]);
            }

            if (str_contains($url, '/oauth2/v2.0/token')) {
                parse_str($request->body(), $params);
                $this->tokenRequests[] = $params;

                return $this->tokenResponse
                    ? Http::response($this->tokenResponse['body'], $this->tokenResponse['status'])
                    : Http::response(['access_token' => 'x', 'id_token' => $this->idToken()]);
            }

            if (str_starts_with($url, 'https://graph.microsoft.com/v1.0/applications(appId=')) {
                if ($this->graphStatus !== 200) {
                    return Http::response(['error' => ['code' => 'Authorization_RequestDenied']], $this->graphStatus);
                }
                if ($request->method() === 'PATCH') {
                    $this->graphPatches[] = $request->data();
                    $this->graphWeb = $request->data()['web'];
                    return Http::response(null, 204);
                }
                return Http::response(['web' => $this->graphWeb]);
            }

            return Http::response('unexpected ' . $url, 500);
        });
    }

    protected function publicJwk(): array
    {
        $details = openssl_pkey_get_details($this->rsaKey)['rsa'];

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'kid' => $this->kid,
            'n' => rtrim(strtr(base64_encode($details['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['e']), '+/', '-_'), '='),
        ];
    }

    protected string $nonce = 'nonce-de-test';

    protected function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => $this->issuer(),
            'aud' => $this->clientId,
            'tid' => $this->tenant,
            'oid' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'preferred_username' => 'Jane.Doe@Example.com',
            'name' => 'Jane Doe',
            'nonce' => $this->nonce,
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600,
        ], $overrides);
    }

    protected function idToken(array $overrides = [], ?string $kid = null): string
    {
        openssl_pkey_export($this->rsaKey, $pem);

        return JWT::encode($this->claims($overrides), $pem, 'RS256', $kid ?? $this->kid);
    }
}
