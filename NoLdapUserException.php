<?php

namespace yetopen\usuarioLdap;

use Exception;

/**
 * Class NoLdapUserException
 */
class NoLdapUserException extends Exception
{
    public $message = "LDAP user not found";
}
