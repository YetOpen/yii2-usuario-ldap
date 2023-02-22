<?php

namespace yetopen\usuarioLdap;

use Exception;

/**
 * Class MultipleUsersFoundException
 * @package yetopen\usuarioLdap
 */
class MultipleUsersFoundException extends Exception
{
    public $message = "Multiple LDAP users found";
}
