<?php namespace Ladylain\MicrosoftLogin\Classes\Exceptions;

use Exception;

/**
 * SsoException porte un message destiné à l'utilisateur, sans jeton ni secret.
 *
 * Le détail technique éventuel (code AADSTS…) va dans $detail, journalisé mais pas affiché.
 */
class SsoException extends Exception
{
    public function __construct(string $message, public readonly ?string $detail = null)
    {
        parent::__construct($message);
    }
}
