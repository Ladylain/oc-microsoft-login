<?php namespace Ladylain\MicrosoftLogin\Classes;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\ConnectionException;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;

/**
 * RedirectUriRegistrar déclare l'URI de redirection du site dans l'application Entra ID, via Graph.
 *
 * Prérequis (une fois) : permission d'application Application.ReadWrite.OwnedBy avec consentement
 * administrateur, et l'application propriétaire d'elle-même. Les autres URI ne sont jamais retirées.
 */
class RedirectUriRegistrar
{
    const GRAPH = 'https://graph.microsoft.com/v1.0';

    public function __construct(protected OidcClient $client, protected string $clientId)
    {
    }

    /**
     * register ajoute l'URI si elle manque ; renvoie false si elle était déjà déclarée.
     */
    public function register(string $redirectUri): bool
    {
        if (!str_starts_with($redirectUri, 'https://')) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.register.https_only', ['uri' => $redirectUri]));
        }

        $token = $this->client->graphToken();
        $url = self::GRAPH . "/applications(appId='" . rawurlencode($this->clientId) . "')";

        $web = $this->call(fn () => Http::withToken($token)->timeout(OidcClient::HTTP_TIMEOUT)->acceptJson()->get($url, ['$select' => 'web']))['web'] ?? [];
        $uris = $web['redirectUris'] ?? [];

        if (in_array($redirectUri, $uris, true)) {
            return false;
        }

        // « web » est remplacé en entier par Graph : on renvoie ses autres réglages tels quels
        unset($web['redirectUriSettings']);
        $web['redirectUris'] = array_values(array_merge($uris, [$redirectUri]));

        $this->call(fn () => Http::withToken($token)->timeout(OidcClient::HTTP_TIMEOUT)->acceptJson()->patch($url, ['web' => $web]));

        return true;
    }

    protected function call(callable $request): array
    {
        try {
            $response = $request();
        }
        catch (ConnectionException $ex) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.unreachable'), $ex->getMessage());
        }

        if ($response->status() === 403 || $response->status() === 404) {
            throw new SsoException(
                __('ladylain.microsoftlogin::lang.register.forbidden'),
                (string) ($response->json('error.code') ?? $response->status())
            );
        }

        if (!$response->successful()) {
            throw new SsoException(
                __('ladylain.microsoftlogin::lang.errors.generic', ['code' => $response->json('error.code') ?? $response->status()])
            );
        }

        return $response->json() ?? [];
    }
}
