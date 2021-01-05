<?php

namespace yetopen\usuarioLdap;

use Adldap\Adldap;
use Adldap\AdldapException;
use Adldap\Connections\Provider;
use Adldap\Models\User as AdldapUser;
use Adldap\Schemas\OpenLDAP;
use Da\User\Controller\AdminController;
use Da\User\Controller\RecoveryController;
use Da\User\Event\ResetPasswordEvent;
use Da\User\Event\UserEvent;
use Da\User\Model\Profile;
use Da\User\Model\User;
use ErrorException;
use Yii;
use yii\base\Component;
use yii\base\Event;
use Da\User\Controller\SecurityController;
use Da\User\Event\FormEvent;
use yii\db\ActiveRecord;
use yii\helpers\VarDumper;

/**
 * Class Module
 * @package yetopen\usuarioLdap
 *
 * @property Adldap $ldapProvider
 * @property Adldap $secondLdapProvider
 * @property array $ldapConfig
 * @property array $secondLdapConfig
 * @property bool $createLocalUsers
 * @property bool|array $defaultRoles
 * @property bool $syncUsersToLdap
 * @property int $defaultUserId
 * @property string $userIdentificationLdapAttribute
 * @property bool|array $otherOrganizationalUnits
 *
 * @property array $mapUserARtoLDAPattr
 */
class Module extends Component
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
     * Specify a session key where to save the LDAP username in case of LDAP authentication
     * set NULL in order to not save the username in session
     * @var string
     */
    public $sessionKeyForUsername = 'ldap_username';

    /**
     * @var null|string
     */
    public $userIdentificationLdapAttribute = NULL;

    /**
     * Array of names of the alternative Organizational Units
     * If set the login will be tried also on the OU specified
     * @var false
     */
    public $otherOrganizationalUnits = FALSE;

    /**
     * Determines if password recovery is disabled or not for LDAP users.
     * If this property is set to FALSE it requires $passwordRecoveryRedirect to be specified.
     * It defaults to TRUE.
     * @var bool
     */
    public $allowPasswordRecovery = FALSE;

    /**
     * The URL where the user will be redirected when trying to recover the password.
     * This parameter will be processed by yii\helpers\Url::to().
     * It's required when $allowPasswordRecovery is set to FALSE.
     * @var null | string | array
     */
    public $passwordRecoveryRedirect = NULL;

    /**
     * It's the category of all the logs of the module, defaults to 'YII2_USUARIO_LDAP'
     * @var string
     */
    public $logCategory = 'YII2_USUARIO_LDAP';

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
        // TODO check all the module params
        $this->checkLdapConfiguration();

        // For second LDAP parameters use first one as default if not set
        if (is_null($this->secondLdapConfig)) $this->secondLdapConfig = $this->ldapConfig;

        $this->events();

        parent::init();
    }

    /**
     * Instantiate the providers based on the application configuration
     */
    public function initAdLdap() {
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
                    if($config['schema'] === OpenLDAP::class) {
                        // Extracts the part of the base_dn after the OU and put it in $accountSuffix['rest']
                        preg_match('/(,ou=[\w]+)*(?<rest>,.*)*/i', $config['account_suffix'], $accountSuffix);
                        // Rebuilds the account_suffix
                        $config['account_suffix'] = ",ou=".$otherOrganizationalUnit.$accountSuffix['rest'];
                        // Sets a provider with the new account_suffix
                    } else {
                        // Rebuilds the base_dn
                        $config['base_dn'] = "ou={$otherOrganizationalUnit},{$config['base_dn']},";
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
            $this->error("Error connecting to LDAP Server", $e->getMessage());
            parent::init();
            return;
        }
        // Connect second LDAP
        $ad2 = new Adldap();
        $ad2->addProvider($this->secondLdapConfig);
        try {
            $ad2->connect();
            $this->secondLdapProvider = $ad2;
        } catch (adLDAPException $e) {
            $this->error("Error connecting to the second LDAP Server", $e);
            parent::init();
            return;
        }
    }

    public function events() {
        Event::on(SecurityController::class, FormEvent::EVENT_BEFORE_LOGIN, function (FormEvent $event) {
            $this->initAdLdap();
            /* @var $provider Provider */
            $provider = Yii::$app->usuarioLdap->ldapProvider;
            $form = $event->getForm();

            $username = $form->login;
            $password = $form->password;

            // If somehow username or password are empty, lets usuario handle it
            if(empty($username) || empty($password)) {
                $this->info("Either username or password was not specified");
                return;
            }

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            if (!$this->tryAuthentication($provider, $username, $password)) {
                $failed = TRUE;
                if($this->otherOrganizationalUnits) {
                    foreach ($this->otherOrganizationalUnits as $otherOrganizationalUnit) {
                        $prov = $provider->getProvider($otherOrganizationalUnit);
                        if($this->tryAuthentication($prov, $username, $password)) {
                            $failed = FALSE;
                            break;
                        }
                    }
                }
                if($failed) {
                    $this->warning("Authentication failed");
                    // Failed.
                    return;
                }
            }

            $username_inserted = $username;
            $ldap_user = NULL;
            foreach (['uid', 'cn', 'samaccountname'] as $ldapAttr) {
                try {
                    $ldap_user = $this->findLdapUser($username, $ldapAttr, 'ldapProvider');
                } catch (NoLdapUserException $e) {
                    continue;
                }
            }

            if(is_null($ldap_user)) {
                throw new NoLdapUserException("Impossible to find LDAP user");
            }
            $username = $ldap_user->getAttribute('uid')[0];
            if (empty($username)) {
                $username = $username_inserted;
            }
            $user = User::findOne(['username' => $username]);
            if (empty($user)) {
                $this->info("User not found in the application database");
                if ($this->createLocalUsers) {
                    $this->info("The user will be created");
                    $user = new User();
                    $user->username = $username;
                    $user->password = uniqid();
                    // Gets the email from the ldap user
                    $user->email = $ldap_user->getEmail();
                    $user->confirmed_at = time();
                    if (!$user->save()) {
                        $this->error("Error saving the new user in the database", $user->errors);
                        // FIXME handle save error
                        return;
                    }

                    // Gets the profile name of the user from the CN of the LDAP user
                    $profile = Profile::findOne(['user_id' => $user->id]);
                    $profile->name = $ldap_user->getAttribute('cn')[0];
                    // Tries to save only if the name has been found
                    if ($profile->name && !$profile->save()) {
                        $this->error("Error saving the new profile in the database", $profile->errors);
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
                    $this->info("The user will be logged using the default user");
                    $user = User::findOne($this->defaultUserId);
                    if (empty($user)) {
                        // The default User wasn't found, it has to be created
                        $user = new User();
                        $user->id = $this->defaultUserId;
                        $user->email = "default@user.com";
                        $user->confirmed_at = time();
                        if (!$user->save()) {
                            $this->error("Error creating the default user", $user->errors);
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
            Yii::$app->session->set($this->sessionKeyForUsername, $user->username);
            Yii::info("Utente '{$user->username}' accesso LDAP eseguito con successo", "ACCESSO_LDAP");
            return Yii::$app->controller->goBack()->send();
        });
        Event::on(RecoveryController::class, FormEvent::EVENT_BEFORE_REQUEST, function (FormEvent $event) {
            $this->initAdLdap();
            /**
             * After a user recovery request is sent, it checks if the email given is one of a LDAP user.
             * If the the uurlser is found and the parameter `allowPasswordRecovery` is set to FALSE, it redirect
             * to the url specified in `passwordRecoveryRedirect`
             */
            $form = $event->getForm();
            $email = $form->email;
            try {
                $ldapUser = $this->findLdapUser($email, 'mail', 'ldapProvider');
            } catch (NoLdapUserException $e) {
                $this->info("User $email not found");
                return;
            }
            if(!is_null($ldapUser) && !$this->allowPasswordRecovery) {
                Yii::$app->controller->redirect($this->passwordRecoveryRedirect)->send();
                Yii::$app->end();
            }
        });
        if ($this->syncUsersToLdap !== TRUE) {
            // If I don't have to sync the local users to LDAP I don't need next events
            return;
        }
        Event::on(SecurityController::class, FormEvent::EVENT_AFTER_LOGIN, function (FormEvent $event) {
            $this->initAdLdap();
            /**
             * After a successful login if no LDAP user is found I create it.
             * Is the only point where I can have the user password in clear for existing users
             * and sync them to LDAP
             */
            $form = $event->getForm();

            $username = $form->login;
            try {
                $ldapUser = $this->findLdapUser($username, 'cn');
            } catch (NoLdapUserException $e) {
                $password = $form->password;
                $user = User::findOne(['username' => $username]);
                $user->password = $password;
                $this->createLdapUser($user);
            }
        });
        Event::on(AdminController::class, UserEvent::EVENT_AFTER_CREATE, function (UserEvent $event) {
            $this->initAdLdap();
            $user = $event->getUser();
            try {
                $this->createLdapUser($user);
            } catch (\yii\base\ErrorException $e) {
                // Probably the user already exists on LDAP
                // TODO:
                // I can arrive here if:
                // * LDAP access is enabled with local user creation and local users sync is enabled with the same LDAP
                // * local users sync is enabled with an already populated LDAP and somebody tries to create a user with an existing username in LDAP
                // None of the presented cases at the moment is part of our specifications
            }
        });
        Event::on(AdminController::class, ActiveRecord::EVENT_BEFORE_UPDATE, function (UserEvent $event) {
            $this->initAdLdap();
            $user = $event->getUser();

            // Use the old username to find the LDAP user because it could be modified and in LDAP I still have the old one
            $username = $user->oldAttributes['username'];
            try {
                $ldapUser = $this->findLdapUser($username, 'cn');
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
            $this->initAdLdap();
            $token = $event->getToken();
            $user = $token->user;
            try {
                $ldapUser = $this->findLdapUser($user->username, 'cn');
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
            $this->initAdLdap();
            $user = $event->getUser();
            try {
                $ldapUser = $this->findLdapUser($user->username, 'cn');
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
     * @param $provider Provider
     * @param $username string
     * @param $password string
     * @return boolean
     * @throws MultipleUsersFoundException
     * @throws \Adldap\Auth\BindException
     * @throws \Adldap\Auth\PasswordRequiredException
     * @throws \Adldap\Auth\UsernameRequiredException
     */
    private function tryAuthentication($provider, $username, $password) {
        $this->info("Trying authentication for {$username} with provider", $provider);
        // Tries to authenticate the user with the standard configuration
        if($provider->auth()->attempt($username, $password)) {
            $this->info("User successfully authenticated");
            return TRUE;
        }
        // If the suffix was not specified it is impossibile to search for another attribute
        if(empty($this->ldapConfig['account_suffix'])) {
            return FALSE;
        }

        $this->info("Default authentication didn't work, it will be tried again with another attribute");

        // Finds the user first using the username as uid then, if nothing was found, as cn
        // FIXME should it be done for the mail key too?
        $user = NULL;
        foreach (['uid', 'cn', 'samaccountname'] as $ldapAttr) {
            try {
                $user = $this->findLdapUser($username, $ldapAttr, 'ldapProvider');
            } catch (NoLdapUserException $e) {
                continue;
            }
            break;
        }
        if(is_null($user)) {
            $this->warning("Couldn't find the user using another attribute");
            return FALSE;
        }
        $this->info("Found user with attribute `$ldapAttr`");

        // Gets the user authentication attribute from the distinguished name
        $dn = $user->getAttribute($provider->getSchema()->distinguishedName(), 0);
        // Since an account can be matched by several attributes I take the one used in the dn for doing the bind
        preg_match('/(?<prefix>.*)=.*'.$this->ldapConfig['account_suffix'].'/i', $dn, $prefix);

        $config = $this->ldapConfig;
        $config['account_prefix'] = $prefix['prefix']."=";
        $userAuth = $user->getAttribute($prefix['prefix'], 0);

        // The provider configuration needs to be reset with the new account_prefix
        $provider->setConfiguration($config);
        $provider->connect();
        $success = FALSE;
        if($provider->auth()->attempt($userAuth, $password)) {
            $this->info("User successfully authenticated");
            $success = TRUE;
        }
        $provider->setConfiguration($this->ldapConfig);
        $provider->connect();
        return $success;
    }

    /**
     * @param $username
     * @param string $key
     * @param string $ldapProvider
     * @return mixed
     * @throws MultipleUsersFoundException
     * @throws \yetopen\usuarioLdap\NoLdapUserException
     */
    private function findLdapUser ($username, $key, $ldapProvider = 'secondLdapProvider') {
        $ldapUser = Yii::$app->usuarioLdap->{$ldapProvider}->search()
            ->where($this->userIdentificationLdapAttribute ?: $key, '=', $username)
            ->first();

        if (empty($ldapUser)) {
            throw new NoLdapUserException();
        }

        if (is_array($ldapUser)) {
            throw new MultipleUsersFoundException();
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

    /**
     * Checks the plugin configuration params
     * @throws LdapConfigurationErrorException
     */
    private function checkLdapConfiguration() {
        if(!isset($this->ldapConfig)) {
            throw new LdapConfigurationErrorException('ldapConfig must be specified');
        }
        if(!isset($this->ldapConfig['schema'])) {
            throw new LdapConfigurationErrorException('schema must be specified');
        }
        if($this->ldapConfig['schema'] === OpenLDAP::class) {
            $this->checkOpenLdapConfiguration();
        }
        if($this->allowPasswordRecovery === FALSE && is_null($this->passwordRecoveryRedirect)) {
            throw new LdapConfigurationErrorException('passwordRecoveryRedirect must be specified if allowPasswordRecovery is set to FALSE');
        }
    }

    /**
     * Checks the plugin configuration params when the schema is set as OpenLDAP
     * @throws LdapConfigurationErrorException
     */
    private function checkOpenLdapConfiguration() {
        if(!isset($this->ldapConfig['account_suffix'])) {
            throw new LdapConfigurationErrorException(OpenLDAP::class.' requires an account suffix');
        }
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function error($message, $object = NULL) {
        $this->log('error', $message, $object);
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function warning($message, $object = NULL) {
        $this->log('warning', $message, $object);
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function info($message, $object = NULL) {
        $this->log('info', $message, $object);
    }

    /**
     * @param $level string
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function log($level, $message, $object) {
        if(!empty($object)) {
            $message .= ": ".VarDumper::dumpAsString($object);
        }
        Yii::$level($message, $this->logCategory);
    }
}