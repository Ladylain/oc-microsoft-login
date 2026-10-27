<?php namespace Ladylain\MicrosoftLogin\Controllers;

use Log;
use Flash;
use Config;
use Backend;
use Request;
use Session;
use Redirect;
use BackendAuth;
use Illuminate\Support\Str;
use Backend\Models\AccessLog;
use Backend\Classes\Controller;
use Backend\Models\User as BackendUser;
use October\Rain\Auth\AuthException;
use Ladylain\MicrosoftLogin\Models\Identity;
use Ladylain\MicrosoftLogin\Models\Settings;
use Ladylain\MicrosoftLogin\Classes\OidcClient;
use Ladylain\MicrosoftLogin\Classes\UserResolver;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;

/**
 * Sso : départ vers Microsoft (start) et retour après authentification (callback).
 *
 * Les deux actions sont publiques (l'utilisateur n'est pas encore connecté).
 * L'état de la demande (state, nonce, vérificateur PKCE) vit en session et ne sert qu'une fois.
 */
class Sso extends Controller
{
    const SESSION_KEY = 'ladylain.microsoftlogin.flow';

    const FLOW_TTL = 600;

    protected $publicActions = ['start', 'callback'];

    public function start()
    {
        try {
            if (!Settings::isReady()) {
                throw new SsoException(__('ladylain.microsoftlogin::lang.errors.disabled'));
            }

            $flow = [
                'state' => Str::random(40),
                'nonce' => Str::random(40),
                'verifier' => OidcClient::generateVerifier(),
                'expires' => time() + self::FLOW_TTL,
            ];

            $url = $this->client()->authorizationUrl($flow['state'], $flow['nonce'], $flow['verifier'], Settings::redirectUri());
        }
        catch (SsoException $ex) {
            return $this->fail($ex);
        }

        Session::put(self::SESSION_KEY, $flow);

        return Redirect::away($url);
    }

    public function callback()
    {
        $flow = Session::pull(self::SESSION_KEY);

        try {
            if (!Settings::isReady()) {
                throw new SsoException(__('ladylain.microsoftlogin::lang.errors.disabled'));
            }

            $state = get('state');
            if (!is_array($flow) || ($flow['expires'] ?? 0) < time() || !is_string($state) || !hash_equals($flow['state'], $state)) {
                throw new SsoException(__('ladylain.microsoftlogin::lang.errors.state'));
            }

            if (is_string($error = get('error'))) {
                throw OidcClient::errorFromCode($error, (string) get('error_description'));
            }

            $code = get('code');
            if (!is_string($code) || $code === '') {
                throw new SsoException(__('ladylain.microsoftlogin::lang.errors.state'), 'code absent');
            }

            $claims = $this->client()->exchangeCode($code, $flow['verifier'], Settings::redirectUri(), $flow['nonce']);

            [$user, $identity] = (new UserResolver)->resolve($claims);

            $this->signIn($user, $identity);
        }
        catch (SsoException $ex) {
            return $this->fail($ex);
        }

        return Backend::redirectIntended('backend');
    }

    /**
     * signIn applique les mêmes garde-fous que la connexion par mot de passe :
     * compte activé, non suspendu ni banni, journal d'accès.
     */
    protected function signIn(BackendUser $user, Identity $identity): void
    {
        if (!$user->is_activated) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.not_activated'));
        }

        try {
            BackendAuth::findThrottleByUserId($user->getKey(), Request::ip())->check();
        }
        catch (AuthException $ex) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.suspended'), $ex->getMessage());
        }

        BackendAuth::login($user, (bool) Config::get('backend.force_remember', false));

        $identity->last_login_at = now();
        $identity->save();

        AccessLog::add($user);

        Log::info(sprintf('[MicrosoftLogin] connexion de « %s » avec le compte Microsoft %s', $user->login, $identity->email));
    }

    protected function fail(SsoException $ex)
    {
        Log::notice('[MicrosoftLogin] connexion refusée : ' . $ex->getMessage() . ($ex->detail ? " ({$ex->detail})" : ''));

        Flash::error($ex->getMessage());

        return Backend::redirect('backend/auth/signin');
    }

    protected function client(): OidcClient
    {
        return new OidcClient(Settings::instance());
    }
}
