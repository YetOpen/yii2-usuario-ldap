<?php

namespace yetopen\usuario_ldap;

use Adldap\Adldap;
use Adldap\AdldapException;
use Yii;
use yii\base\Model as BaseModule;
use yii\base\Event;
use Da\User\Controller\SecurityController;
use Da\User\Event\FormEvent;
use Da\User\Model\User;

class Module extends BaseModule
{
    public $ldapProvider;

    public $secondLdapProvider;

    // Contiene le informazioni per connettersi a LDAP
    public $ldapConfig;

    // Contiene le informazioni per connettersi a LDAP
    public $secondLdapConfig;

    // Determina se l'applicazione possa scrivere su LDAP
    public $updateLdap;

    /**
     * If TRUE when a user pass the LDAP authentication, on first LDAP server, it is created locally
     * If FALSE a default users with id -1 is used for the session
     * @var bool
     */
    public $createLocalUsers = TRUE;

    /**
     * Roles to be assigned to new local users
     * @var bool|array
     */
    public $defaultRoles = FALSE;

    /**
     * If TRUE changes to local users are synchronized with the second LDAP server specified.
     * Including creation and deletion of an user.
     * @var bool
     */
    public $syncUsersToLdap = FALSE;

    public function init()
    {
        // For second LDAP parameters use first one as default if not set
        if (is_null($this->secondLdapConfig)) $this->secondLdapConfig = $this->ldapConfig;

        // Connect first LDAP
        $ad = new Adldap();
        $ad->addProvider($this->ldapConfig);
        try {
            $ad->connect();
            $this->ldapProvider = $ad;
        } catch (adLDAPException $e) {
            var_dump($e);
            die;
        }
        // Connect second LDAP
        $ad2 = new Adldap();
        $ad2->addProvider($this->secondLdapConfig);
        try {
            $ad2->connect();
            $this->secondLdapProvider = $ad2;
        } catch (adLDAPException $e) {
            var_dump($e);
            die;
        }
        $this->events();
        parent::init();
    }

    public function events() {
        Event::on(SecurityController::class, FormEvent::EVENT_BEFORE_LOGIN, function (FormEvent $event) {
            $provider = Yii::$app->usuarioLdap->ldapProvider;
            $form = $event->getForm();

            $username = $form->login;
            $password = $form->password;

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            try {
                if ($provider->auth()->attempt($username, $password)) {
                    // Passed.
                } else {
                    // Failed.
                    return;
                }
            } catch (\Adldap\Auth\UsernameRequiredException $e) {
                // The user didn't supply a username.
                return;
            } catch (\Adldap\Auth\PasswordRequiredException $e) {
                // The user didn't supply a password.
                return;
            }

            $user = User::findOne(['username' => $username]);
            if(empty($user)) {
                if ($this->createLocalUsers) {
                    $user = new User();
                    $user->username = $username;
                    $user->password = $password;
                    $user->email = $username . "@ldap.com"; //FIXME prendere l'email da utente LDAP https://adldap2.github.io/Adldap2/#/searching
                    $user->confirmed_at = time();
//                $user->blocked_at     = time();
                    if (!$user->save()) {
                        return;
                    }
                    if ($this->defaultRoles !== FALSE) {
                        // FIXME to be implemented
                    }
                } else {
                    // FIXME use a default user with id -1
                }
            }
            // Now I have a valid user which passed LDAP authentication, lets login it
            $userIdentity = User::findIdentity($user->id);
            $duration = $form->rememberMe ? $form->module->rememberLoginLifespan : 0;

            return Yii::$app->getUser()->login($userIdentity, $duration);
        });
    }
}
