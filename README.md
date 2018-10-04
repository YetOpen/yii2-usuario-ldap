Yii2 Usuario Ldap
=================
An yii2 extension to syncronize LDAP users in [2amigos/usuario](https://github.com/2amigos/yii2-usuario)

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist yetopen/yii2-usuario-ldap "*"
```

or add

```
"yetopen/yii2-usuario-ldap": "*"
```

to the require section of your `composer.json` file.

Installazione per sviluppo
-----------------------------

Aggiungere al composer sotto la voce `"require-dev"`

```
"yetopen/yii2-usuario-ldap": "@dev"
```

e sotto `"repositories"`

```json
{
    "type": "path",
    "url": "{path_all_estensione}"
}
```

quindi eseguire
```bash
php composer.phar update yetopen/yii2-usuario-ldap
```

Configurazione
--------------

In web.php nella cartella config inserire

```php
//...
'bootstrap' => ['log', 'usuarioLdap'],
//...
'components' => [
    //...
    'usuarioLdap' => [
        'class' => 'yetopen\usuario_ldap\Module',
        'ldapConfig' => [
            'hosts' => ['host.example.com'],
            'base_dn' => 'dc=mydomain,dc=local',
            'account_prefix' => 'cn=',
            'account_suffix' => ',ou=Users,dc=mydomain,dc=local',
            'use_ssl'          => true,
            'username' => 'admin',
            'password' => 'password',
        ],
        'createLocalUsers' => TRUE,
        'defaultRoles' => ['standardUser'],
        'syncUsersToLdap' => TRUE,
        'secondLdapConfig' => [
            'hosts' => ['host.example.com'],
            'base_dn' => 'dc=mydomain,dc=local',
            'account_prefix' => 'cn=',
            'account_suffix' => ',ou=Users,dc=mydomain,dc=local',
            'username' => 'admin',
            'password' => 'password',
        ],
    ],
    //...
]
```
modificando i parametri con quelli opportuni.
#### Parameters meaning
* **ldapConfig**: all the parameters for connecting to LDAP server as documented in [Adldap2](https://adldap2.github.io/Adldap2/#/setup?id=options)
* **createLocalUsers**: if TRUE when a user pass the LDAP authentication, on first LDAP server, it is created locally. If FALSE a default users with ID specified in defaultUserId is used for the session
* **defaultRoles**: if specified the role/s will be assigned to the new created users. Can be set as an array. By default this is FALSE
* **syncUsersToLdap**: if TRUE changes to local users are synchronized with the second LDAP server specified. Including creation and deletion of an user.
* **secondLdapConfig**: if specified this is used as LDAP server for sync the local users.
* **defaultUserId**: if createLocalUsers is set to FALSE, specify the ID of the default user. Defaults to `-1`

By default this is equal to _ldapConfig_
