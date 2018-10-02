<?php

namespace yetopen\usuario_ldap;

use Yii;
use yii\base\Model as BaseModule;
use yii\helpers\ArrayHelper;
use adLDAP\adLDAPException;
//use \Adldap\Configuration\DomainConfiguration;
use adLDAP\adLDAP as Adldap;
use yii\base\Event;
use app\controllers\user\SecurityController;
use Da\User\Event\FormEvent;
use Da\User\Model\User;

class Module extends BaseModule
{
    public static $ldapProvider;

    // Contiene le informazioni per connettersi a LDAP
    public $ldapConfig;

    // È il suffisso degli utenti in LDAP
    public $accountSuffix;

    // Determina se l'applicazione possa scrivere su LDAP
    public $updateLdap;

    public function init()
    {
        $ad = new Adldap($this->ldapConfig);
        $ad->setAccountSuffix($this->accountSuffix);
        try {
            $ad->connect();
            self::$ldapProvider = $ad;
        } catch (adLDAPException $e) {
            var_dump($e);
            die;
        }
        $this->events();
        parent::init();
    }

    public function events() {
        Event::on(SecurityController::class, FormEvent::EVENT_BEFORE_LOGIN, function (FormEvent $event) {
            $provider = Yii::$app->usuarioLdap::$ldapProvider;
            $form = $event->getForm();

            $username = $form->login;
            $password = $form->password;
            if(!$provider->authenticate($username, $password)) {
                return;
            }

            $userIdentity = User::findIdentity(User::findOne(['username' => $username])->id);
            if(empty($userIdentity)) {
                $userIdentity = new User();
                $userIdentity->username       = $username;
                $userIdentity->password       = $password;
                $userIdentity->email          = $username."@ldap.com"; //FIXME prendere l'email da utente LDAP
                $userIdentity->confirmed_at   = time();
                $userIdentity->blocked_at     = time();
            }
            $duration = $form->rememberMe ? $form->module->rememberLoginLifespan : 0;

            return Yii::$app->getUser()->login($userIdentity, $duration);

        });
    }
}
