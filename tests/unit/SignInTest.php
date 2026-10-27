<?php namespace Ladylain\MicrosoftLogin\Tests\Unit;

use Db;
use Backend;
use BackendAuth;
use PluginTestCase;
use Backend\Models\User as BackendUser;
use Ladylain\MicrosoftLogin\Models\Identity;
use Ladylain\MicrosoftLogin\Models\Settings;
use Ladylain\MicrosoftLogin\Controllers\Sso;
use Ladylain\MicrosoftLogin\Classes\UserResolver;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;
use Ladylain\MicrosoftLogin\Tests\FakeMicrosoft;

require_once __DIR__ . '/../FakeMicrosoft.php';

class SignInTest extends PluginTestCase
{
    use FakeMicrosoft;

    public function tearDown(): void
    {
        // AuthManager est un singleton statique (utilisateur et cache de check()) :
        // sans cela, l'état d'authentification d'un test déborde sur le suivant
        BackendAuth::logout();
        \Backend\Classes\AuthManager::forgetInstance();

        parent::tearDown();
    }

    protected function makeUser(string $login, string $email, array $extra = []): BackendUser
    {
        $user = new BackendUser;
        $user->forceFill(array_merge([
            'login' => $login,
            'email' => $email,
            'first_name' => $login,
            'password' => 'Mot-de-passe-42',
            'password_confirmation' => 'Mot-de-passe-42',
            'is_activated' => true,
        ], $extra));
        $user->save();

        return $user;
    }

    // --- Association des comptes -------------------------------------------------

    public function testFirstLoginLinksByEmailCaseInsensitively()
    {
        $user = $this->makeUser('jane', 'jane.doe@example.com');

        [$found, $identity] = (new UserResolver)->resolve($this->claims());

        $this->assertSame($user->id, $found->id);
        $this->assertFalse($identity->exists, 'la liaison n\'est enregistrée qu\'après une connexion réussie');
        $this->assertSame('jane.doe@example.com', $identity->email);
    }

    public function testLinkedAccountIsFoundByOidEvenIfEmailChanged()
    {
        $user = $this->makeUser('jane', 'ancienne@example.com');
        Identity::create(['user_id' => $user->id, 'tenant_id' => $this->tenant, 'object_id' => $this->claims()['oid'], 'email' => 'ancienne@example.com']);

        [$found, $identity] = (new UserResolver)->resolve($this->claims(['preferred_username' => 'nouvelle@example.com']));

        $this->assertSame($user->id, $found->id);
        $this->assertSame('nouvelle@example.com', $identity->email);
    }

    public function testNoAccountIsRefusedAndNothingIsCreated()
    {
        $count = BackendUser::count();

        try {
            (new UserResolver)->resolve($this->claims(['preferred_username' => 'inconnu@example.com']));
            $this->fail('exception attendue');
        }
        catch (SsoException $ex) {
            $this->assertStringContainsString('inconnu@example.com', $ex->getMessage());
        }

        $this->assertSame($count, BackendUser::count());
    }

    public function testAccountLinkedToAnotherMicrosoftAccountIsRefused()
    {
        $user = $this->makeUser('jane', 'jane.doe@example.com');
        Identity::create(['user_id' => $user->id, 'tenant_id' => $this->tenant, 'object_id' => 'ancien-oid', 'email' => 'jane.doe@example.com']);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('déjà lié');
        (new UserResolver)->resolve($this->claims());
    }

    public function testSeveralMatchingAccountsAreRefused()
    {
        $this->makeUser('jane', 'jane.doe@example.com');
        $this->makeUser('jane2', 'jane.smith@example.com');

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('Plusieurs');
        (new UserResolver)->resolve($this->claims(['email' => 'jane.smith@example.com']));
    }

    public function testDeletedAccountIsRefused()
    {
        $user = $this->makeUser('jane', 'jane.doe@example.com');
        Identity::create(['user_id' => $user->id, 'tenant_id' => $this->tenant, 'object_id' => $this->claims()['oid']]);
        $user->delete();

        $this->expectException(SsoException::class);
        (new UserResolver)->resolve($this->claims());
    }

    // --- Réglages -----------------------------------------------------------------

    public function testSecretIsEncryptedAtRestAndSettingsValidated()
    {
        $this->configureSettings();

        $raw = Db::table('system_settings')->where('item', 'ladylain_microsoftlogin_settings')->value('value');
        $this->assertStringNotContainsString('Sup3r~Secret.Value', $raw);
        $this->assertTrue(Settings::isReady());

        $this->expectException(\October\Rain\Database\ModelException::class);
        $this->configureSettings(['tenant_id' => 'common']);
    }

    public function testEnabledSettingsRequireCredentials()
    {
        $this->expectException(\October\Rain\Database\ModelException::class);
        $this->configureSettings(['client_secret' => null, 'client_id' => null]);
    }

    // --- Parcours complet ---------------------------------------------------------

    protected function startFlow(): array
    {
        $response = $this->get(Backend::url('ladylain/microsoftlogin/sso/start'));
        $response->assertRedirect();
        parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->nonce = $query['nonce'];

        return $query;
    }

    public function testFullSignInFlow()
    {
        $user = $this->makeUser('jane', 'jane.doe@example.com');
        $this->configureSettings();
        $this->fakeMicrosoft();

        $query = $this->startFlow();
        $this->assertSame(Settings::redirectUri(), $query['redirect_uri']);

        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query(['code' => 'abc', 'state' => $query['state']]))
            ->assertRedirect(Backend::url('backend'));

        $this->assertTrue(BackendAuth::check());
        $this->assertSame($user->id, BackendAuth::getUser()->id);

        $identity = Identity::where('user_id', $user->id)->first();
        $this->assertNotNull($identity->last_login_at);
        $this->assertSame($this->tenant, $identity->tenant_id);
        $this->assertNull(session(Sso::SESSION_KEY), 'l\'état de la demande ne sert qu\'une fois');
    }

    public function testCallbackWithWrongStateIsRefused()
    {
        $this->makeUser('jane', 'jane.doe@example.com');
        $this->configureSettings();
        $this->fakeMicrosoft();
        $this->startFlow();

        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?code=abc&state=falsifie')
            ->assertRedirect(Backend::url('backend/auth/signin'));

        $this->assertFalse(BackendAuth::check());
        $this->assertEmpty($this->tokenRequests, 'aucun code n\'est échangé si le state est faux');
    }

    public function testCallbackReplayIsRefused()
    {
        $this->makeUser('jane', 'jane.doe@example.com');
        $this->configureSettings();
        $this->fakeMicrosoft();
        $query = $this->startFlow();
        $callback = Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query(['code' => 'abc', 'state' => $query['state']]);

        $this->get($callback);
        BackendAuth::logout();

        $this->get($callback)->assertRedirect(Backend::url('backend/auth/signin'));
        $this->assertFalse(BackendAuth::check());
    }

    public function testSuspendedAndInactiveAccountsCannotSignIn()
    {
        $user = $this->makeUser('jane', 'jane.doe@example.com', ['is_activated' => false]);
        $this->configureSettings();
        $this->fakeMicrosoft();

        $query = $this->startFlow();
        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query(['code' => 'abc', 'state' => $query['state']]))
            ->assertRedirect(Backend::url('backend/auth/signin'));
        $this->assertFalse(BackendAuth::check());
        $this->assertFalse(Identity::where('user_id', $user->id)->exists());

        $user->is_activated = true;
        $user->save();
        BackendAuth::findThrottleByUserId($user->id, '127.0.0.1')->ban();

        $query = $this->startFlow();
        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query(['code' => 'abc', 'state' => $query['state']]))
            ->assertRedirect(Backend::url('backend/auth/signin'));
        $this->assertFalse(BackendAuth::check());
    }

    public function testCancelOnMicrosoftPageShowsMessage()
    {
        $this->configureSettings();
        $this->fakeMicrosoft();
        $query = $this->startFlow();

        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query([
            'error' => 'access_denied',
            'error_description' => 'AADSTS65004: User declined to consent.',
            'state' => $query['state'],
        ]))->assertRedirect(Backend::url('backend/auth/signin'));

        $this->assertFalse(BackendAuth::check());
    }

    public function testDisabledPluginRefusesStart()
    {
        $this->configureSettings(['enabled' => false]);

        $this->get(Backend::url('ladylain/microsoftlogin/sso/start'))
            ->assertRedirect(Backend::url('backend/auth/signin'));
    }

    public function testSettingsPageShowsRedirectUriAndTestButton()
    {
        $this->makeUser('admin', 'jane.doe@example.com', ['is_superuser' => true]);
        $this->configureSettings();
        $this->fakeMicrosoft();

        // Connexion par le parcours Microsoft, puis ouverture des réglages
        $query = $this->startFlow();
        $this->get(Backend::url('ladylain/microsoftlogin/sso/callback') . '?' . http_build_query(['code' => 'abc', 'state' => $query['state']]));

        $this->get(Backend::url('system/settings/update/ladylain/microsoftlogin/settings'))
            ->assertOk()
            ->assertSee(Settings::redirectUri())
            ->assertSee('onMicrosoftLoginTest')
            ->assertDontSee('Sup3r~Secret.Value');
    }

    public function testSignInPageShowsButtonOnlyWhenReady()
    {
        $this->configureSettings(['enabled' => false]);
        $this->get(Backend::url('backend/auth/signin'))->assertOk()->assertDontSee('microsoftlogin-button');

        $this->configureSettings();
        $this->get(Backend::url('backend/auth/signin'))->assertOk()->assertSee('microsoftlogin-button');
    }
}
