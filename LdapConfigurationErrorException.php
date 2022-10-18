<?php

namespace yetopen\usuarioLdap;


use Exception;

/**
 * Class LdapConfigurationException
 * @package yetopen\usuarioLdap
 */
class LdapConfigurationErrorException extends Exception
{
    public $message = "LDAP configuration error";
}
