<?php

namespace yetopen\usuarioLdap;

use Da\User\Event\UserEvent;
use Da\User\Model\User;

class LdapUserEvent extends UserEvent
{
    const EVENT_AFTER_LDAP_USER_CREATE = 'afterLdapUserCreate';
    /**
     * @var array
     */
    public $ldapConfiguration;

    public function __construct(User $user, array $ldapConfiguration, array $config = [])
    {
        $this->ldapConfiguration = $ldapConfiguration;
        parent::__construct($user, $config);
    }
}