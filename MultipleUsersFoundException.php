<?php

namespace dmstr\usuarioLdapExtension;

use Exception;

/**
 * Class MultipleUsersFoundException
 * @package dmstr\usuarioLdapExtension
 */
class MultipleUsersFoundException extends Exception
{
    public $message = "Multiple LDAP users found";
}
