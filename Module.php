<?php

namespace yetopen\usuario_ldap;

use Adldap\Adldap;
use Adldap\AdldapException;
use Adldap\Connections\Provider;
use Adldap\Models\Attributes\AccountControl;
use Adldap\Models\User as AdldapUser;
use Da\User\Controller\AdminController;
use Da\User\Controller\RecoveryController;
use Da\User\Event\ResetPasswordEvent;
use Da\User\Event\UserEvent;
use Da\User\Model\Profile;
use Da\User\Model\User;
use ErrorException;
use yetopen\usuario_ldap\NoLdapUserException;
use yetopen\usuario_ldap\RoleNotFoundException;
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

    /**
     * Stores the second LDAP provider
     * @var Adldap
     */
    public $secondLdapProvider;

    /**
     * Parameters for connecting to LDAP server as documented in https://adldap2.github.io/Adldap2/#/setup?id=options
     * @var array
     */
    public $ldapConfig;

    /**
     * Parameters for connecting to the second LDAP server
     * @var array
     */
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
     * Specify the default ID of the User used for the session.
     * It is used only when $createLocalUsers is set to FALSE.
     * @var integer
     */
    public $defaultUserId = -1;

    /**
     * @var null
     */
    public $userIdentificationLdapAttribute = NULL;

    /**
     * Array of names of the alternative Organizational Units
     * If set the login will be tried also on the OU specified
     * @var false
     */
    public $otherOrganizationalUnits = FALSE;

    private static $mapUserARtoLDAPattr = [
        'sn' => 'username',
        'uid' => 'username',
        'mail' => 'email',
    ];

    /**
     * {@inheritdoc}
     */
    public function init()
    {
        // TODO check the types of the module params

        // For second LDAP parameters use first one as default if not set
        if (is_null($this->secondLdapConfig)) $this->secondLdapConfig = $this->ldapConfig;

        // Connect first LDAP
        $ad = new Adldap();
        $ad->addProvider($this->ldapConfig);
        try {
            $ad->connect();
            // If otherOrganizationalUnits setting is configured, attemps the login with the other OU
            if($this->otherOrganizationalUnits) {
                $config = $this->ldapConfig;
                // Extracts the part of the base_dn after the OU and put it in $accountSuffix['rest']
                foreach ($this->otherOrganizationalUnits as $otherOrganizationalUnit) {
                    if(isset($config['account_suffix'])) {
                        // Extracts the part of the base_dn after the OU and put it in $accountSuffix['rest']
                        preg_match('/(,ou=[\w]+)*(?<rest>,.*)*/i', $config['account_suffix'], $accountSuffix);
                        // Rebuilds the account_suffix
                        $config['account_suffix'] = ",ou=".$otherOrganizationalUnit.$accountSuffix['rest'];
                        // Sets a provider with the new account_suffix
                    } else {
                        // Rebuilds the base_dn
                        $config['base_dn'] = "ou=".$otherOrganizationalUnit.$config['base_dn'].',';
                    }
                    // Sets a provider with the configuration
                    $ad->addProvider($config, $otherOrganizationalUnit);
                    $ad->connect($otherOrganizationalUnit);
                    // Sets the config as the original
                    $config = $this->ldapConfig;
                }
            }
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
            /* @var $provider Adldap */
            $provider = Yii::$app->usuarioLdap->ldapProvider;
            $form = $event->getForm();

            $username = $form->login;
            $password = $form->password;

            // If somehow username or password are empty, lets usuario handle it
            if(empty($username) || empty($password)) {
                return;
            }

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            if (!$provider->auth()->attempt($username, $password)) {
                $failed = TRUE;
                if($this->otherOrganizationalUnits) {
                    foreach ($this->otherOrganizationalUnits as $otherOrganizationalUnit) {
                        $prov = $provider->getProvider($otherOrganizationalUnit);
                        if($prov->auth()->attempt($username, $password)) {
                            $failed = FALSE;
                            break;
                        }
                    }
                }
                if($failed) {
                    // Failed.
                    return;
                }
            }

            $username_inserted = $username;
            $username = $this->findLdapUser($username)->getAttribute('uid')[0];
            $user = User::findOne(['username' => $username ?: $username_inserted]);
            if (empty($user)) {
                if ($this->createLocalUsers) {
                    $user = new User();
                    $user->username = $username ?: $username_inserted;
                    $user->password = $password;
                    // Gets the email from the ldap user
                    $user->email = $this
                        ->findLdapUser($username ?: $username_inserted, $username ? 'uid' : 'cn', 'ldapProvider')
                        ->getEmail();
                    $user->confirmed_at = time();
                    if (!$user->save()) {
                        // FIXME handle save error
                        return;
                    }

                    // Gets the profile name of the user from the CN of the LDAP user
                    $profile = Profile::findOne(['user_id' => $user->id]);
                    $profile->name = $this
                        ->findLdapUser($username ?: $username_inserted, $username ? 'uid' : 'cn', 'ldapProvider')
                        ->getAttribute('cn')[0];
                    // Tries to save only if the name has been found
                    if ($profile->name && !$profile->save()) {
                        // FIXME handle save error
                    }

                    if ($this->defaultRoles !== FALSE) {
                        // FIXME this should be checked in init()
                        if(!is_array($this->defaultRoles)) {
                            throw new ErrorException('defaultRoles parameter must be an array');
                        }
                        $this->assignRoles($user->id);
                    }

                    // Triggers the EVENT_AFTER_CREATE event
                    $user->trigger(UserEvent::EVENT_AFTER_CREATE, new UserEvent($user));
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
                        if ($this->defaultRoles !== FALSE) {
                            // FIXME this should be checked in init()
                            if(!is_array($this->defaultRoles)) {
                                throw new ErrorException('defaultRoles parameter must be an array');
                            }
                            $this->assignRoles($user->id);
                        }
                    }

                    $user->username = $username;
                }
            }

            // Now I have a valid user which passed LDAP authentication, lets login it
            $userIdentity = User::findIdentity($user->id);
            $duration = $form->rememberMe ? $form->module->rememberLoginLifespan : 0;
            Yii::$app->getUser()->login($userIdentity, $duration);
            Yii::info("Utente '{$user->username}' accesso LDAP eseguito con successo", "ACCESSO_LDAP");
            return Yii::$app->getResponse()->redirect(Yii::$app->request->referrer)->send();
        });
        if ($this->syncUsersToLdap !== TRUE) {
            // If I don't have to sync the local users to LDAP I don't need next events
            return;
        }
        Event::on(SecurityController::class, FormEvent::EVENT_AFTER_LOGIN, function (FormEvent $event) {
            /**
             * After a successful login if no LDAP user is found I create it.
             * Is the only point where I can have the user password in clear for existing users
             * and sync them to LDAP
             */
            $form = $event->getForm();

            $username = $form->login;
            try {
                $ldapUser = $this->findLdapUser($username);
            } catch (NoLdapUserException $e) {
                $password = $form->password;
                $user = User::findOne(['username' => $username]);
                $user->password = $password;
                $this->createLdapUser($user);
            }
        });
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

            // Set LDAP user attributes from local user if changed
            foreach (self::$mapUserARtoLDAPattr as $ldapAttr => $userAttr) {
                if ($user->isAttributeChanged($userAttr)) {
                    $ldapUser->setAttribute($ldapAttr, $user->$userAttr);
                }
            }
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
        Event::on(RecoveryController::class, ResetPasswordEvent::EVENT_AFTER_RESET, function (ResetPasswordEvent $event) {
            $token = $event->getToken();
            $user = $token->user;
            try {
                $ldapUser = $this->findLdapUser($user->username);
            } catch (NoLdapUserException $e) {
                // Unable to find the user in ldap, if I have the password in cleare I create it
                // these case typically happens when the sync is enabled and we already have users
                if (!empty($user->password)) {
                    $this->createLdapUser($user);
                }
                return;
            }
            if (!empty($user->password)) {
                // If clear password is specified I update it also in LDAP
                $ldapUser->setAttribute('userPassword', '{SHA}'. base64_encode(pack('H*', sha1($user->password))));
            }

            if (!$ldapUser->save()) {
                throw new ErrorException("Impossible to modify the LDAP user");
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
     * @param string $key
     * @return mixed
     * @throws \yetopen\usuario_ldap\NoLdapUserException
     */
    private function findLdapUser ($username, $key = 'cn', $ldapProvider = 'secondLdapProvider') {
        $ldapUser = Yii::$app->usuarioLdap->{$ldapProvider}->search()
            ->where($this->userIdentificationLdapAttribute ?: $key, '=', $username)
            ->first();
        if (empty($ldapUser)) {
            throw new NoLdapUserException("Impossible to find the LDAP user");
        }
        if(get_class($ldapUser) !== AdldapUser::class) {
            throw new NoLdapUserException("The search for the user returned an instance of the class ".get_class($ldapUser));
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
        ]);

        // Set LDAP user attributes from local user if changed
        foreach (self::$mapUserARtoLDAPattr as $ldapAttr => $userAttr) {
                $ldapUser->setAttribute($ldapAttr, $user->$userAttr);
        }

        $ldapUser->setAttribute('userPassword', '{SHA}'. base64_encode(pack('H*', sha1($user->password))));

        foreach (self::$mapUserARtoLDAPattr as $ldapAttr => $userAttr) {
            if ($user->isAttributeChanged($userAttr)) {
                $ldapUser->setAttribute($ldapAttr, $user->$userAttr);
            }
        }

        if (!$ldapUser->save()) {
            throw new ErrorException("Impossible to create the LDAP user");
        }
    }

    /**
     * @param integer $userId
     * @throws ErrorException
     * @throws RoleNotFoundException
     */
    private function assignRoles($userId) {
        $auth = Yii::$app->authManager;
        foreach ($this->defaultRoles as $roleName) {
            if(!is_string($roleName)) {
                throw new ErrorException('The role name must be a string');
            }
            if(!($role = $auth->getRole($roleName))) {
                throw new RoleNotFoundException($roleName);
            }

            $auth->assign($role, $userId);
        }
    }
}
