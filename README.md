# Yii2 Usuario LDAP

An yii2 extension to authenticate and/or syncronize users against LDAP for [2amigos/yii2-usuario](https://github.com/2amigos/yii2-usuario).

## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run:

```
php composer.phar require --prefer-dist yetopen/yii2-usuario-ldap "*"
```

or add

```
"yetopen/yii2-usuario-ldap": "*"
```

to the require section of your `composer.json` file.

## Configuration

Add in your config (`config/web.php` for the basic app):

```php
//...
'bootstrap' => ['log', 'usuarioLdap'],
//...
'components' => [
    //...
    'usuarioLdap' => [
        'class' => 'yetopen\usuarioLdap\UsuarioLdapComponent',
        'ldapConfig' => [
            'hosts' => ['host.example.com'],
            'base_dn' => 'dc=mydomain,dc=local',
            'account_prefix' => 'cn=',
            'account_suffix' => ',ou=Users,dc=mydomain,dc=local',
            'use_ssl' => true,
            'username' => 'bind_username',
            'password' => 'bind_password',
        ],
        'createLocalUsers' => TRUE,
        'defaultRoles' => ['standardUser'],
        'syncUsersToLdap' => TRUE,
        'secondLdapConfig' => [
            'hosts' => ['host.example.com'],
            'base_dn' => 'dc=mydomain,dc=local',
            'account_prefix' => 'cn=',
            'account_suffix' => ',ou=Users,dc=mydomain,dc=local',
            'username' => 'bind_username',
            'password' => 'bind_password',
        ],
        'allowPasswordRecovery' => FALSE,
        'passwordRecoveryRedirect' => ['/controller/action']
    ],
    //...
]
```
adapting parameters to your setup. 

#### Configuration options

* **ldapConfig**: all the parameters for connecting to LDAP server as documented in [Adldap2](https://adldap2.github.io/Adldap2/#/setup?id=options)
* **createLocalUsers**: if TRUE when a user successfully authenticate against the first LDAP server is created locally in Yii database. If FALSE a default users with ID specified in `defaultUserId` is used for the session
* **defaultRoles**: if specified the role/s will be assigned to the users created by the extension. Can be set as an array. Default to FALSE
* **secondLdapConfig**: if specified this is used as LDAP server for sync the local users, if not specified this is equal to _ldapConfig_
* **syncUsersToLdap**: if TRUE changes to local users are synchronized to the second LDAP server. This includes creation and deletion of an user
* **defaultUserId**: if `createLocalUsers` is set to FALSE must contain the ID of an user to be used as local. Defaults to `-1`
* **allowPasswordRecovery**: if TRUE it will enable password recovery process, otherwise it will redirect the LDAP users to the url specified in `passwrdRecoveryRedirect`. Defaults to FALSE.
* **passwordRecoveryRedirect**: when `allowPasswordRecovery` is set to FALSE specifies the URL where the user will be redirected when trying to recover the password. This parameter will be processed by yii\helpers\Url::to().
* **logCategory**: it's the log category that will be passed when the module logs something, defaults to _YII2_USUARIO_LDAP_

#### Log configuration

To log all the messages about the module in one single file, configure under `targets` of log config file
```php
[
    'class' => 'yii\log\FileTarget', // or another target if you prefer
    // Gets all the log and exceptions messages of the module
    'categories' => [
        'YII2_USUARIO_LDAP',
        'yetopen\usuarioLdap\NoLdapUserException',
        'yetopen\usuarioLdap\LdapConfigurationErrorException',
        'yetopen\usuarioLdap\MultipleUsersFoundException',
        'yetopen\usuarioLdap\RoleNotFoundException',
    ],
    'logFile' => '@runtime/logs/usuario_ldap.log', // or the log file destination that you prefer
]
```