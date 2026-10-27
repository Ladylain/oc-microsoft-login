<?php namespace Ladylain\MicrosoftLogin\Models;

use Backend;
use System\Models\SettingModel;

/**
 * Réglages de l'application Entra ID utilisée pour la connexion.
 *
 * Le secret client est chiffré en base (clé APP_KEY) et n'est jamais réaffiché.
 */
class Settings extends SettingModel
{
    use \October\Rain\Database\Traits\Validation;
    use \October\Rain\Database\Traits\Encryptable;

    public $settingsCode = 'ladylain_microsoftlogin_settings';

    public $settingsFields = 'fields.yaml';

    protected $encryptable = ['client_secret'];

    public $rules = [
        'tenant_id' => 'nullable|regex:/^[A-Za-z0-9.-]+$/|not_in:common,organizations,consumers',
        'client_id' => 'nullable|uuid',
        'auth_method' => 'in:secret,certificate',
        'client_secret' => 'nullable|max:255',
        'cert_path' => 'nullable|max:255',
        'cert_pub_path' => 'nullable|max:255',
        'button_label' => 'nullable|max:80',
    ];

    public $customMessages = [
        'tenant_id.not_in' => 'ladylain.microsoftlogin::lang.settings.tenant_id_single',
    ];

    public function initSettingsData()
    {
        $this->enabled = false;
        $this->auth_method = 'secret';
    }

    /**
     * beforeValidate rend la configuration obligatoire seulement quand la connexion est activée.
     */
    public function beforeValidate()
    {
        if (!$this->enabled) {
            return;
        }

        $required = $this->auth_method === 'certificate'
            ? ['tenant_id', 'client_id', 'cert_path', 'cert_pub_path']
            : ['tenant_id', 'client_id', 'client_secret'];

        foreach ($required as $field) {
            $this->rules[$field] = 'required|' . $this->rules[$field];
        }
    }

    public function getAuthMethodOptions(): array
    {
        return [
            'secret' => 'ladylain.microsoftlogin::lang.settings.auth_secret',
            'certificate' => 'ladylain.microsoftlogin::lang.settings.auth_certificate',
        ];
    }

    /**
     * isReady : le bouton n'apparaît que si la connexion est activée et complète.
     */
    public static function isReady(): bool
    {
        $s = static::instance();

        if (!$s->enabled || !$s->tenant_id || !$s->client_id) {
            return false;
        }

        return $s->auth_method === 'certificate'
            ? $s->cert_path && $s->cert_pub_path
            : (bool) $s->client_secret;
    }

    /**
     * redirectUri à déclarer dans Entra ID (plateforme « Web »).
     */
    public static function redirectUri(): string
    {
        return Backend::url('ladylain/microsoftlogin/sso/callback');
    }

    /**
     * mailerSettings : réglages d'Office365Mailer s'il est installé et configuré, sinon null.
     */
    public static function mailerSettings(): ?array
    {
        $class = \Ladylain\Office365Mailer\Models\Settings::class;

        if (!class_exists($class)) {
            return null;
        }

        $mailer = $class::instance();
        $values = [
            'tenant_id' => $mailer->tenant_id,
            'client_id' => $mailer->client_id,
            'cert_path' => $mailer->cert_path,
            'cert_pub_path' => $mailer->cert_pub_path,
        ];

        return in_array(null, $values, true) || in_array('', $values, true) ? null : $values;
    }

    /**
     * importFromMailer reprend tenant, application et certificat d'Office365Mailer (sans activer la connexion).
     */
    public function importFromMailer(): bool
    {
        if (!$values = static::mailerSettings()) {
            return false;
        }

        foreach ($values as $key => $value) {
            $this->$key = $value;
        }
        $this->auth_method = 'certificate';
        $this->save();

        return true;
    }

    /**
     * resolvePath accepte un chemin absolu ou relatif à la racine du site, comme Office365Mailer.
     */
    public static function resolvePath(string $path): string
    {
        return str_starts_with($path, '/') ? $path : base_path($path);
    }
}
