<?php

namespace yetopen\usuario_ldap;

use Adldap\Adldap;
use Adldap\AdldapException;
use Adldap\Connections\Provider;
use Adldap\Models\Attributes\AccountControl;
use Adldap\Models\User as AdldapUser;
use Da\User\Controller\AdminController;
use Da\User\Event\UserEvent;
use Da\User\Model\User;
use ErrorException;
use NoLdapUserException;
use Yii;
use yii\base\Model as BaseModule;
use yii\base\Event;
use Da\User\Controller\SecurityController;
use Da\User\Event\FormEvent;
use yii\db\ActiveRecord;

class Module extends BaseModule
{
    /**
     * Stores the LDAP provider
     * @var Adldap
     */
    public $ldapProvider;

    public $secondLdapProvider;

    // Contiene le informazioni per connettersi a LDAP
    public $ldapConfig;

    // Contiene le informazioni per connettersi a LDAP
    public $secondLdapConfig;

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

    /**
     * Specify the default User ID of the User from which to get the identity from.
     * It is used only when $createLocalUsers is set to FALSE.
     * @var integer
     */
    public $defaultUserId = -1;

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

            // If somehow username or password are empty, let usuario handle it
            if(empty($username) || empty($password)) {
                return;
            }

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            try {
                if (!$provider->auth()->attempt($username, $password)) {
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
            if (empty($user)) {
                if ($this->createLocalUsers) {
                    $user = new User();
                    $user->username = $username;
                    $user->password = $password;
                    $user->email = $username . "@ldap.com"; //FIXME prendere l'email da utente LDAP https://adldap2.github.io/Adldap2/#/searching
                    $user->confirmed_at = time();

                    if (!$user->save()) {
                        // FIXME handle save error
                        return;
                    }
                    if ($this->defaultRoles !== FALSE) {
                        // FIXME to be implemented
                    }
                } else {
                    $user = User::findOne($this->defaultUserId);
                    if (empty($user)) {
                        // The default User wasn't found, it has to be created
                        $user = new User();
                        $user->id = $this->defaultUserId;
                        $user->email = "default@user.com";
                        $user->confirmed_at = time();
                        if (!$user->save()) {
                            var_dump($user->getErrors());
                            die;
                            //FIXME handle save error
                            return;
                        }
                    }
                    if ($this->defaultRoles !== FALSE) {
                        // FIXME to be implemented
                    }

                    $user->username = $username;
                    $userIdentity = User::findIdentity($this->defaultUserId);
                    $duration = $form->rememberMe ? $form->module->rememberLoginLifespan : 0;
                    if (Yii::$app->getUser()->login($userIdentity, $duration)) {
                        return Yii::$app->response->redirect(Yii::$app->request->referrer);
                    } else {
                        // FIXME handle login error
                        return;
                    }
                }
            }
            // Now I have a valid user which passed LDAP authentication, lets login it
            $userIdentity = User::findIdentity($user->id);
            $duration = $form->rememberMe ? $form->module->rememberLoginLifespan : 0;

            return Yii::$app->getUser()->login($userIdentity, $duration);
        });
        if ($this->syncUsersToLdap !== TRUE) {
            // If I don't have to sync the local users to LDAP I don't need next events
            return;
        }
        Event::on(AdminController::class, UserEvent::EVENT_BEFORE_CREATE, function (UserEvent $event) {
            $user = $event->getUser();
            $this->createLdapUser($user);

        });
        Event::on(AdminController::class, ActiveRecord::EVENT_BEFORE_UPDATE, function (UserEvent $event) {
            $user = $event->getUser();

            // Use the old username to find the LDAP user because it could be modified and in LDAP I still have the old one
            $username = $user->oldAttributes['username'];
            try {
                $ldapUser = $this->findLdapUser($username);
            } catch (NoLdapUserException $e) {
                // Unable to find the user in ldap, if I have the password in cleare I create it
                // these case typically happens when the sync is enabled and we already have users
                if (!empty($user->password)) {
                    $this->createLdapUser($user);
                }
                return;
            }

            // Set LDAP user attributes from local user
            $ldapUser->setAttribute('sn', empty($user->profile) ? $user->username :  $user->profile->name);
            $ldapUser->setAttribute('gn', empty($user->profile) ? $user->username :  $user->profile->name);
            $ldapUser->setAttribute('mail', $user->email);
            $ldapUser->setAttribute('uid', $user->username);
            if (!empty($user->password)) {
                // If clear password is specified I update it also in LDAP
                $ldapUser->setAttribute('userPassword', '{SHA}'. base64_encode(pack('H*', sha1($user->password))));
            }

            if (!$ldapUser->save()) {
                throw new ErrorException("Impossible to modify the LDAP user");
            }

            if ($username != $user->username) {
                // If username is changed the procedure to change the cn in LDAP is the following
                if (!$ldapUser->rename("cn={$user->username}")) {
                    throw new ErrorException("Impossible to rename the LDAP user");
                }
            }
        });
        Event::on(AdminController::class, ActiveRecord::EVENT_BEFORE_DELETE, function (UserEvent $event) {
            $user = $event->getUser();
            try {
                $ldapUser = $this->findLdapUser($user->username);
            } catch (NoLdapUserException $e) {
                // We don't have a corresponding LDAP user so nothing to delete
                return;
            }

            if (!$ldapUser->delete()) {
                throw new ErrorException("Impossible to delete the LDAP user");
            }
        });
    }

    /**
     * @param $username
     * @return AdldapUser
     * @throws NoLdapUserException
     */
    private function findLdapUser ($username) {
        $ldapUser = Yii::$app->usuarioLdap->secondLdapProvider->search()->where('cn', '=', $username)->first();
        if (empty($ldapUser)) {
            throw new NoLdapUserException("Impossible to find the LDAP user");
        }
        return $ldapUser;
    }

    /**
     * @param $user
     * @throws ErrorException
     */
    private function createLdapUser ($user) {
        $ldapUser = Yii::$app->usuarioLdap->secondLdapProvider->make()->user([
            'cn' => $user->username,
            'sn' => empty($user->profile) ? $user->username :  $user->profile->name,
            'gn' => empty($user->profile) ? $user->username :  $user->profile->name,
            'mail' => $user->email,
            'uid' => $user->username,
            // FIXME Adldap\Models\User has method setPassword but seams to use a LDAP attribute not supported
            'userPassword' => '{SHA}'. base64_encode(pack('H*', sha1($user->password))),
        ]);

        if (!$ldapUser->save()) {
            throw new ErrorException("Impossible to create the LDAP user");
        }
    }
}
