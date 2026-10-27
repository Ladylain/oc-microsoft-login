<?php namespace Ladylain\MicrosoftLogin\Tests\Unit;

use PluginTestCase;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Ladylain\MicrosoftLogin\Classes\OidcClient;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;
use Ladylain\MicrosoftLogin\Tests\FakeMicrosoft;

require_once __DIR__ . '/../FakeMicrosoft.php';

class OidcClientTest extends PluginTestCase
{
    use FakeMicrosoft;

    protected function client(): OidcClient
    {
        return new OidcClient($this->configureSettings());
    }

    public function testAuthorizationUrlUsesTenantPkceAndNonce()
    {
        $this->fakeMicrosoft();
        $url = $this->client()->authorizationUrl('st', 'no', 'verifier-123', 'https://site.test/cb');

        $this->assertStringStartsWith("https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/authorize?", $url);
        parse_str(parse_url($url, PHP_URL_QUERY), $q);
        $this->assertSame('code', $q['response_type']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertSame(OidcClient::codeChallenge('verifier-123'), $q['code_challenge']);
        $this->assertSame('openid profile email', $q['scope']);
        $this->assertSame(['st', 'no'], [$q['state'], $q['nonce']]);
        $this->assertArrayNotHasKey('client_secret', $q, 'le secret ne passe jamais par le navigateur');
    }

    public function testPkceChallengeMatchesRfc7636Example()
    {
        $this->assertSame(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            OidcClient::codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
        );
    }

    public function testExchangeCodeSendsVerifierAndSecretAndReturnsClaims()
    {
        $this->fakeMicrosoft();
        $claims = $this->client()->exchangeCode('the-code', 'verifier-123', 'https://site.test/cb', $this->nonce);

        $this->assertSame('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', $claims['oid']);
        $sent = $this->tokenRequests[0];
        $this->assertSame('authorization_code', $sent['grant_type']);
        $this->assertSame('verifier-123', $sent['code_verifier']);
        $this->assertSame('Sup3r~Secret.Value', $sent['client_secret']);
        $this->assertSame($this->clientId, $sent['client_id']);
    }

    /**
     * @dataProvider invalidTokens
     */
    public function testInvalidIdTokensAreRejected(callable $make)
    {
        $this->fakeMicrosoft();
        $client = $this->client();

        $this->expectException(SsoException::class);
        $client->validateIdToken($make($this), $this->nonce);
    }

    public static function invalidTokens(): array
    {
        return [
            'mauvaise audience' => [fn ($t) => $t->idToken(['aud' => 'autre-appli'])],
            'mauvais émetteur' => [fn ($t) => $t->idToken(['iss' => 'https://login.microsoftonline.com/autre/v2.0'])],
            'autre tenant' => [fn ($t) => $t->idToken(['tid' => '99999999-9999-9999-9999-999999999999'])],
            'nonce rejoué' => [fn ($t) => $t->idToken(['nonce' => 'autre'])],
            'expiré' => [fn ($t) => $t->idToken(['exp' => time() - 3600, 'iat' => time() - 7200, 'nbf' => time() - 7200])],
            'sans oid' => [fn ($t) => $t->idToken(['oid' => null])],
            'HS256 signé avec la clé publique' => [fn ($t) => JWT::encode($t->claims(), 'secret-quelconque-assez-long-pour-hs256', 'HS256', $t->kid)],
            'signature falsifiée' => [fn ($t) => substr($t->idToken(), 0, -6) . 'AAAAAA'],
            'non signé' => [fn ($t) => implode('.', array_slice(explode('.', $t->idToken()), 0, 2)) . '.'],
        ];
    }

    public function testUnknownKeyTriggersOneJwksRefresh()
    {
        $this->fakeMicrosoft();
        $client = $this->client();
        $client->validateIdToken($this->idToken(), $this->nonce); // met les clés en cache

        // Rotation chez Microsoft : nouvelle clé, nouveau kid
        $this->rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->kid = 'test-key-2';

        $claims = $client->validateIdToken($this->idToken(), $this->nonce);
        $this->assertSame($this->tenant, $claims['tid']);
    }

    public function testMicrosoftErrorsAreTranslated()
    {
        $this->fakeMicrosoft();
        $this->tokenResponse = ['status' => 401, 'body' => [
            'error' => 'invalid_client',
            'error_description' => "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x",
        ]];

        try {
            $this->client()->testCredentials();
            $this->fail('exception attendue');
        }
        catch (SsoException $ex) {
            $this->assertStringContainsString('Valeur', $ex->getMessage());
            $this->assertStringNotContainsString('Sup3r~Secret.Value', $ex->getMessage() . $ex->detail);
            $this->assertSame('invalid_client AADSTS7000215: Invalid client secret provided.', $ex->detail);
        }

        $unknown = OidcClient::errorFromCode('invalid_request', 'AADSTS123456: something');
        $this->assertStringContainsString('AADSTS123456', $unknown->getMessage());
        $this->assertStringContainsString('annulée', OidcClient::errorFromCode('access_denied')->getMessage());
    }

    public function testCertificateAssertionIsSignedWithThumbprint()
    {
        $dir = sys_get_temp_dir() . '/mslogin-' . uniqid();
        mkdir($dir);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $cert = openssl_csr_sign(openssl_csr_new(['commonName' => 'test'], $key), null, $key, 30);
        openssl_pkey_export_to_file($key, "$dir/key.pem");
        openssl_x509_export_to_file($cert, "$dir/cert.pem");

        $this->fakeMicrosoft();
        $client = new OidcClient($this->configureSettings([
            'auth_method' => 'certificate',
            'cert_path' => "$dir/key.pem",
            'cert_pub_path' => "$dir/cert.pem",
        ]));
        $client->testCredentials();

        $sent = $this->tokenRequests[0];
        $this->assertArrayNotHasKey('client_secret', $sent);
        $this->assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $sent['client_assertion_type']);

        $header = json_decode(JWT::urlsafeB64Decode(explode('.', $sent['client_assertion'])[0]), true);
        $this->assertSame(OidcClient::base64Url(openssl_x509_fingerprint($cert, 'sha1', true)), $header['x5t']);

        $payload = (array) JWT::decode($sent['client_assertion'], new Key(openssl_pkey_get_details($key)['key'], 'RS256'));
        $this->assertSame($this->clientId, $payload['iss']);
        $this->assertStringEndsWith('/oauth2/v2.0/token', $payload['aud']);

        array_map('unlink', glob("$dir/*"));
        rmdir($dir);
    }

    public function testMissingCertificateGivesClearError()
    {
        $this->fakeMicrosoft();
        $client = new OidcClient($this->configureSettings([
            'auth_method' => 'certificate',
            'cert_path' => 'storage/introuvable.pem',
            'cert_pub_path' => 'storage/introuvable.crt',
        ]));

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('introuvables');
        $client->testCredentials();
    }
}
