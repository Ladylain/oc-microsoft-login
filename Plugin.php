<?php namespace Ladylain\MicrosoftLogin;

use Flash;
use Redirect;
use Event;
use BackendAuth;
use ApplicationException;
use Backend\Models\User as BackendUser;
use System\Controllers\Settings as SettingsController;
use System\Classes\PluginBase;
use System\Classes\SettingsManager;
use Ladylain\MicrosoftLogin\Models\Identity;
use Ladylain\MicrosoftLogin\Classes\OidcClient;
use Ladylain\MicrosoftLogin\Classes\RedirectUriRegistrar;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;
use Ladylain\MicrosoftLogin\Models\Settings;

/**
 * Plugin « Se connecter avec Microsoft » pour le back-office October CMS.
 *
 * Connexion OpenID Connect (code d'autorisation + PKCE) sur un tenant Entra ID unique.
 * Seuls les comptes back-office existants peuvent se connecter : aucun compte n'est créé.
 */
class Plugin extends PluginBase
{
    public function pluginDetails(): array
    {
        return [
            'name' => 'ladylain.microsoftlogin::lang.plugin.name',
            'description' => 'ladylain.microsoftlogin::lang.plugin.description',
            'author' => 'Ladylain',
            'icon' => 'icon-windows',
            'homepage' => 'https://github.com/Ladylain/oc-microsoft-login',
        ];
    }

    public function boot(): void
    {
        Event::listen('backend.auth.extendSigninView', function ($controller) {
            if (!Settings::isReady()) {
                return '';
            }

            return $controller->makePartial(plugins_path('ladylain/microsoftlogin/partials/_signin_button.htm'), [
                'label' => Settings::get('button_label') ?: __('ladylain.microsoftlogin::lang.signin.button'),
            ]);
        });

        BackendUser::extend(function ($model) {
            $model->hasOne['microsoft_identity'] = [Identity::class, 'key' => 'user_id', 'delete' => true];
        });

        // Boutons de la page de réglages (test, déclaration de l'URI, reprise d'Office365Mailer)
        SettingsController::extend(function ($controller) {
            $guard = function () {
                if (!BackendAuth::userHasAccess('ladylain.microsoftlogin.manage_settings')) {
                    throw new ApplicationException(__('ladylain.microsoftlogin::lang.errors.forbidden'));
                }
            };

            $controller->addDynamicMethod('onMicrosoftLoginTest', function () use ($guard) {
                $guard();

                try {
                    (new OidcClient(Settings::instance()))->testCredentials();
                }
                catch (SsoException $ex) {
                    throw new ApplicationException($ex->getMessage());
                }

                Flash::success(__('ladylain.microsoftlogin::lang.guide.test_ok'));
            });

            $controller->addDynamicMethod('onMicrosoftLoginRegister', function () use ($guard) {
                $guard();
                $settings = Settings::instance();

                try {
                    $added = (new RedirectUriRegistrar(new OidcClient($settings), (string) $settings->client_id))
                        ->register(Settings::redirectUri());
                }
                catch (SsoException $ex) {
                    throw new ApplicationException($ex->getMessage());
                }

                Flash::success(__($added ? 'ladylain.microsoftlogin::lang.register.added' : 'ladylain.microsoftlogin::lang.register.exists'));
            });

            $controller->addDynamicMethod('onMicrosoftLoginImportMailer', function () use ($guard) {
                $guard();

                if (!Settings::instance()->importFromMailer()) {
                    throw new ApplicationException(__('ladylain.microsoftlogin::lang.import.missing'));
                }

                Flash::success(__('ladylain.microsoftlogin::lang.import.done'));

                return Redirect::refresh();
            });
        });
    }

    public function register(): void
    {
        $this->registerConsoleCommand('microsoftlogin.register', Console\Register::class);
    }

    public function registerPermissions(): array
    {
        return [
            'ladylain.microsoftlogin.manage_settings' => [
                'tab' => 'ladylain.microsoftlogin::lang.plugin.name',
                'label' => 'ladylain.microsoftlogin::lang.permissions.manage_settings',
            ],
        ];
    }

    public function registerSettings(): array
    {
        return [
            'settings' => [
                'label' => 'ladylain.microsoftlogin::lang.settings.label',
                'description' => 'ladylain.microsoftlogin::lang.settings.description',
                'category' => SettingsManager::CATEGORY_TEAM,
                'icon' => 'icon-windows',
                'class' => Settings::class,
                'order' => 600,
                'keywords' => 'microsoft entra azure sso oidc office365 connexion',
                'permissions' => ['ladylain.microsoftlogin.manage_settings'],
            ],
        ];
    }
}
