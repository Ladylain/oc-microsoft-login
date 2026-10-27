<?php namespace Ladylain\MicrosoftLogin\Console;

use Illuminate\Console\Command;
use Ladylain\MicrosoftLogin\Models\Settings;
use Ladylain\MicrosoftLogin\Classes\OidcClient;
use Ladylain\MicrosoftLogin\Classes\RedirectUriRegistrar;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;

/**
 * microsoftlogin:register prépare la connexion Microsoft d'un site en une commande :
 * reprise éventuelle de la configuration d'Office365Mailer, test, déclaration de l'URI dans Entra ID.
 */
class Register extends Command
{
    protected $signature = 'microsoftlogin:register
        {--import-mailer : Reprendre tenant, application et certificat d\'Office365Mailer}
        {--enable : Activer le bouton une fois l\'URI déclarée}';

    protected $description = 'Déclare l\'URI de redirection de ce site dans l\'application Entra ID';

    public function handle(): int
    {
        $settings = Settings::instance();

        if ($this->option('import-mailer')) {
            if (!$settings->importFromMailer()) {
                $this->error(__('ladylain.microsoftlogin::lang.import.missing'));
                return self::FAILURE;
            }
            $this->info(__('ladylain.microsoftlogin::lang.import.done'));
        }

        $uri = Settings::redirectUri();
        $this->line(__('ladylain.microsoftlogin::lang.register.uri', ['uri' => $uri]));

        try {
            $added = (new RedirectUriRegistrar(new OidcClient($settings), (string) $settings->client_id))->register($uri);
        }
        catch (SsoException $ex) {
            $this->error($ex->getMessage() . ($ex->detail ? " ({$ex->detail})" : ''));
            return self::FAILURE;
        }

        $this->info(__($added ? 'ladylain.microsoftlogin::lang.register.added' : 'ladylain.microsoftlogin::lang.register.exists'));

        if ($this->option('enable')) {
            $settings->enabled = true;
            $settings->save();
            $this->info(__('ladylain.microsoftlogin::lang.register.enabled'));
        }

        return self::SUCCESS;
    }
}
