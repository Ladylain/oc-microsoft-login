<?php namespace Ladylain\MicrosoftLogin\Models;

use Model;
use Backend\Models\User as BackendUser;

/**
 * Identity relie un compte back-office à un compte Microsoft (tenant + identifiant d'objet « oid »).
 *
 * L'oid est stable pour un compte : il sert à reconnaître l'utilisateur même si son e-mail change.
 */
class Identity extends Model
{
    public $table = 'ladylain_microsoftlogin_identities';

    protected $fillable = ['user_id', 'tenant_id', 'object_id', 'email'];

    protected $dates = ['last_login_at'];

    public $belongsTo = [
        'user' => BackendUser::class,
    ];
}
