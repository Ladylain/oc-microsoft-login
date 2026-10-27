<?php namespace Ladylain\MicrosoftLogin\Classes;

use Db;
use Backend\Models\User as BackendUser;
use Ladylain\MicrosoftLogin\Models\Identity;
use Ladylain\MicrosoftLogin\Classes\Exceptions\SsoException;

/**
 * UserResolver retrouve le compte back-office correspondant à un compte Microsoft.
 *
 * 1. Compte déjà lié : par tenant + oid (stable même si l'e-mail change).
 * 2. Première connexion : par e-mail (email, preferred_username, upn), puis liaison.
 * Aucun compte n'est jamais créé ; en cas de doute, la connexion est refusée.
 */
class UserResolver
{
    /**
     * resolve renvoie le compte et sa liaison (non enregistrée si nouvelle).
     * @return array{0: BackendUser, 1: Identity}
     */
    public function resolve(array $claims): array
    {
        $tenantId = (string) $claims['tid'];
        $objectId = (string) $claims['oid'];
        $emails = static::candidateEmails($claims);

        $identity = Identity::where('tenant_id', $tenantId)->where('object_id', $objectId)->first();

        if ($identity) {
            if (!$user = $identity->user) {
                throw new SsoException(__('ladylain.microsoftlogin::lang.errors.account_removed'));
            }

            $identity->email = $emails[0] ?? $identity->email;

            return [$user, $identity];
        }

        if (!$emails) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.no_email'));
        }

        $users = BackendUser::whereIn(Db::raw('lower(email)'), $emails)->get();

        if ($users->isEmpty()) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.no_account', ['email' => $emails[0]]));
        }

        if ($users->count() > 1) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.ambiguous', ['email' => $emails[0]]));
        }

        $user = $users->first();

        // Un compte déjà lié à un autre compte Microsoft (ex. adresse réattribuée) n'est pas repris
        if (Identity::where('user_id', $user->id)->exists()) {
            throw new SsoException(__('ladylain.microsoftlogin::lang.errors.linked_elsewhere', ['email' => $user->email]));
        }

        $identity = new Identity([
            'user_id' => $user->id,
            'tenant_id' => $tenantId,
            'object_id' => $objectId,
            'email' => $emails[0],
        ]);

        return [$user, $identity];
    }

    /**
     * candidateEmails : adresses valides du jeton, en minuscules, sans doublon.
     */
    public static function candidateEmails(array $claims): array
    {
        $emails = [];

        foreach (['email', 'preferred_username', 'upn'] as $claim) {
            $value = strtolower(trim((string) ($claims[$claim] ?? '')));

            if ($value !== '' && filter_var($value, FILTER_VALIDATE_EMAIL)) {
                $emails[] = $value;
            }
        }

        return array_values(array_unique($emails));
    }
}
