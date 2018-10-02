Yii2 Usuario Ldap
=================
An yii2 extension to syncronize LDAP users in Yii

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

Aggiungere al composer sotto la voce `"require-dev"`:

```
"yetopen/yii2-usuario-ldap": "@dev"
```

E sotto `"repositories"`:

```json
{
    "type": "path",
    "url": "{path_all_estensione}"
}
```

Quindi eseguire:
```bash
php composer.phar update yetopen/yii2-usuario-ldap
```
