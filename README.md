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
            'username' => 'admin',
            'password' => 'password',
        ],
        'accountSuffix' => '@mydomain.local',
    ]
    //...
]
```
modificando i parametri con quelli opportuni
