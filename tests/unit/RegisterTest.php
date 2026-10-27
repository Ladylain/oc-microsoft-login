<?php namespace Ladylain\MicrosoftLogin\Tests\Unit;

use Artisan;
use PluginTestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use Ladylain\MicrosoftLogin\Models\Settings;
use Ladylain\MicrosoftLogin\Classes\OidcClient;
use Ladylain\MicrosoftLogin\Classes\RedirectUriRegistrar;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;
use Ladylain\MicrosoftLogin\Tests\FakeMicrosoft;

require_once __DIR__ . '/../FakeMicrosoft.php';

class RegisterTest extends PluginTestCase
{
    use FakeMicrosoft;

    protected function registrar(): RedirectUriRegistrar
    {
        return new RedirectUriRegistrar(new OidcClient($this->configureSettings()), $this->clientId);
    }

    public function testAddsUriAndKeepsOtherSitesAndSettings()
    {
        $this->fakeMicrosoft();
        $uri = 'https://intranet.example.com/admin/ladylain/microsoftlogin/sso/callback';

        $this->assertTrue($this->registrar()->register($uri));

        $this->assertCount(1, $this->graphPatches);
        $web = $this->graphPatches[0]['web'];
        $this->assertSame([
            'https://other-site.example.com/admin/ladylain/microsoftlogin/sso/callback',
            $uri,
        ], $web['redirectUris']);
        $this->assertSame('https://www.example.com', $web['homePageUrl'], 'les autres réglages « web » sont conservés');
        $this->assertArrayHasKey('implicitGrantSettings', $web);
        $this->assertArrayNotHasKey('redirectUriSettings', $web);
        $this->assertSame('client_credentials', $this->tokenRequests[0]['grant_type']);
    }

    public function testAlreadyRegisteredUriIsNotPatchedAgain()
    {
        $this->fakeMicrosoft();
        $registrar = $this->registrar();
        $uri = 'https://intranet.example.com/admin/ladylain/microsoftlogin/sso/callback';

        $registrar->register($uri);
        $this->assertFalse($registrar->register($uri));
        $this->assertCount(1, $this->graphPatches);
    }

    public function testMissingPermissionGivesSetupInstructions()
    {
        $this->fakeMicrosoft();
        $this->graphStatus = 403;

        try {
            $this->registrar()->register('https://site.fr/admin/ladylain/microsoftlogin/sso/callback');
            $this->fail('exception attendue');
        }
        catch (SsoException $ex) {
            $this->assertStringContainsString('Application.ReadWrite.OwnedBy', $ex->getMessage());
            $this->assertSame('Authorization_RequestDenied', $ex->detail);
        }
    }

    public function testHttpUriIsRefusedBeforeCallingMicrosoft()
    {
        $this->fakeMicrosoft();

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('APP_URL');
        try {
            $this->registrar()->register('http://site.local/admin/ladylain/microsoftlogin/sso/callback');
        }
        finally {
            $this->assertEmpty($this->tokenRequests);
        }
    }

    public function testConsoleCommandRegistersAndEnables()
    {
        $this->configureSettings(['enabled' => false]);
        $this->fakeMicrosoft();

        $out = new BufferedOutput;
        $this->assertSame(0, Artisan::call('microsoftlogin:register', ['--enable' => true], $out));
        $this->assertStringContainsString(Settings::redirectUri(), $out->fetch());

        $this->assertContains(Settings::redirectUri(), $this->graphWeb['redirectUris']);
        Settings::clearInternalCache();
        $this->assertTrue((bool) Settings::instance()->enabled);
    }

    public function testConsoleCommandFailsClearlyWithoutPermission()
    {
        $this->configureSettings(['enabled' => false]);
        $this->fakeMicrosoft();
        $this->graphStatus = 403;

        $out = new BufferedOutput;
        $this->assertSame(1, Artisan::call('microsoftlogin:register', ['--enable' => true], $out));
        $this->assertStringContainsString('Application.ReadWrite.OwnedBy', $out->fetch());

        Settings::clearInternalCache();
        $this->assertFalse((bool) Settings::instance()->enabled, 'pas d\'activation si l\'URI n\'a pas pu être déclarée');
    }
}
