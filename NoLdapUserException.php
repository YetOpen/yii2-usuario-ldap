<?php

namespace dmstr\usuarioLdapExtension;

use Exception;

/**
 * Class NoLdapUserException
 */
class NoLdapUserException extends Exception
{
    public $message = "LDAP user not found";
}
