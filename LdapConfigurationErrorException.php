<?php

namespace dmstr\usuarioLdapExtension;


use Exception;

/**
 * Class LdapConfigurationException
 * @package dmstr\usuarioLdapExtension
 */
class LdapConfigurationErrorException extends Exception
{
    public $message = "LDAP configuration error";
}
