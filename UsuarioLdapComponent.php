<?php

namespace yetopen\usuarioLdap;

use Adldap\Adldap;
use Adldap\AdldapException;
use Adldap\Connections\Provider;
use Adldap\Models\Attributes\AccountControl;
use Adldap\Models\Concerns\HasUserAccountControl;
use Adldap\Models\Model;
use Adldap\Models\User as AdldapUser;
use Adldap\Query\Collection;
use Adldap\Schemas\OpenLDAP;
use Da\User\Controller\SettingsController;
use Da\User\Controller\AdminController;
use Da\User\Controller\RecoveryController;
use Da\User\Controller\RegistrationController;
use Da\User\Controller\SecurityController;
use Da\User\Dictionary\UserSourceType;
use Da\User\Event\FormEvent;
use Da\User\Event\ResetPasswordEvent;
use Da\User\Event\UserEvent;
use Da\User\Form\LoginForm;
use Da\User\Form\SettingsForm;
use Da\User\Model\Assignment;
use Da\User\Model\Profile;
use Da\User\Model\User;
use Da\User\Query\UserQuery;
use Da\User\Traits\AuthManagerAwareTrait;
use Da\User\Traits\ContainerAwareTrait;
use ErrorException;
use yii\helpers\ArrayHelper;
use Yii;
use yii\base\Component;
use yii\base\Event;
use yii\db\ActiveRecord;
use yii\helpers\VarDumper;
use yii\web\Application as WebApplication;

/**
 * Class Module
 *
 * @package yetopen\usuarioLdap
 *
 * @property Adldap|null $_ldapProvider
 * @property Adldap|null $_secondLdapProvider
 * @property array $ldapConfig
 * @property array $secondLdapConfig
 * @property bool $createLocalUsers
 * @property bool|array $defaultRoles
 * @property bool $syncUsersToLdap
 * @property int $defaultUserId
 * @property string $userIdentificationLdapAttribute
 * @property bool|array $otherOrganizationalUnits
 * @property array $mapUserARtoLDAPattr
 *
 * @property-read Adldap|null $ldapProvider
 * @property-read Adldap|null $secondLdapProvider
 */
class UsuarioLdapComponent extends Component
{
    use ContainerAwareTrait;
    use AuthManagerAwareTrait;

    /**
     * Stores the LDAP provider
     *
     * @var Adldap|null
     */
    private $_ldapProvider;

    /**
     * Stores the second LDAP provider
     *
     * @var Adldap|null
     */
    private $_secondLdapProvider;

    /**
     * Parameters for connecting to LDAP server as documented in https://adldap2.github.io/Adldap2/#/setup?id=options
     *
     * @var array
     */
    public $ldapConfig;

    /**
     * Parameters for connecting to the second LDAP server, this will be the LDAP server where users are synced if $syncUsersToLdap is TRUE
     * Default NULL and it will assume same config as $ldapConfig
     * If FALSE second LDAP connection will not be established
     * Parameters for connecting to the second LDAP server
     *
     * @var array
     */
    public $secondLdapConfig;

    /**
     * If TRUE when a user pass the LDAP authentication, on first LDAP server, it is created locally
     * If FALSE a default users with id -1 is used for the session
     *
     * @var bool
     */
    public $createLocalUsers = true;

    /**
     * Roles to be assigned to new local users
     *
     * @var bool|array
     */
    public $defaultRoles = false;

    /**
     * If set different from `false`, it will be forced on the newly created users as their "account control".
     * By default, it is set to `false`.
     * The attribute is present in `ActiveDirectory` style schemas only, the standard for activating the account is `512`.
     * @see HasUserAccountControl
     * @var false|int|string|AccountControl
     */
    public $defaultUserAccountControl = FALSE;

    /**
     * If TRUE changes to local users are synchronized with the second LDAP server specified.
     * Including creation and deletion of an user.
     *
     * @var bool
     */
    public $syncUsersToLdap = false;

    /**
     * Specify the default ID of the User used for the session.
     * It is used only when $createLocalUsers is set to FALSE.
     *
     * @var integer
     */
    public $defaultUserId = -1;

    /**
     * Specify a session key where to save the LDAP username in case of LDAP authentication
     * set NULL in order to not save the username in session
     *
     * @var string
     */
    public $sessionKeyForUsername = 'ldap_username';

    /**
     * @var null|string
     */
    public $userIdentificationLdapAttribute = null;

    /**
     * Array of names of the alternative Organizational Units
     * If set the login will be tried also on the OU specified
     *
     * @var false
     */
    public $otherOrganizationalUnits = false;

    /**
     * Determines if password recovery is disabled or not for LDAP users.
     * If this property is set to FALSE it requires $passwordRecoveryRedirect to be specified.
     * It defaults to TRUE.
     *
     * @var bool
     */
    public $allowPasswordRecovery = false;

    /**
     * The URL where the user will be redirected when trying to recover the password.
     * This parameter will be processed by yii\helpers\Url::to().
     * It's required when $allowPasswordRecovery is set to FALSE.
     *
     * @var null | string | array
     */
    public $passwordRecoveryRedirect = null;

    /**
     * It's the category of all the logs of the module, defaults to 'YII2_USUARIO_LDAP'
     *
     * @var string
     */
    public $logCategory = 'YII2_USUARIO_LDAP';

    /**
     * If set, when new LDAP users are created or assigned to a role, they will be added to groups based on this mapping.
     * It must be an array where the key corresponds to a Yii2 RBAC role and as value either the DN or an array of DNs
     * of groups to which user assigned to that role have to be added.
     * For example:
     * ```php
     * // Yii2 users with assigned the role "admin" will be automatically added to the "administrator" LDAP group
     * 'rolesGroupsMapping' => [
     *      'admin' => ['administrators']
     * ]
     * ```
     * @warning Users must be directly assigned to the roles to be added to the LDAP group.
     * @var array
     */
    public $rolesGroupsMap = [];

    private static $mapUserARtoLDAPattr = [
        'sn' => 'username',
        'cn' => 'username',
        'uid' => 'username',
        'userPrincipalName' => 'username',
        'samaccountname' => 'username',
        'email' => 'email',
        'mail' => 'email',
    ];

    private static $ldapAttrs = ['uid', 'samaccountname', 'userPrincipalName', 'email', 'mail', 'cn'];

    /**
     * Used for cashing the user once is found
     * @var $ldapUser AdldapUser
     */
    private $ldapUser;
    private $ldapUsers;

    /**
     * {@inheritdoc}
     */
    public function init()
    {
        $this->initI18n();

        // TODO check all the module params
        $this->checkLdapConfiguration();

        // For second LDAP parameters use first one as default if not set
        if (is_null($this->secondLdapConfig)) {
            $this->secondLdapConfig = $this->ldapConfig;
        }

        $this->events();

        parent::init();
    }

    protected function initI18n()
    {
        Yii::setAlias("@usuarioLdap", __DIR__);
        $config = [
            'class' => 'yii\i18n\PhpMessageSource',
            'basePath' => "@usuarioLdap/messages",
            'forceTranslation' => true,
        ];
        $globalConfig = ArrayHelper::getValue(Yii::$app->i18n->translations, "usuarioLdap*", []);
        if (!empty($globalConfig)) {
            $config = array_merge($config, is_array($globalConfig) ? $globalConfig : (array)$globalConfig);
        }
        if (!empty($this->i18n) && is_array($this->i18n)) {
            $config = array_merge($config, $this->i18n);
        }
        Yii::$app->i18n->translations["usuarioLdap*"] = $config;
    }
    public function getLdapProvider()
    {
        if (empty($this->_ldapProvider)) {
            $this->initAdLdap();
        }
        return $this->_ldapProvider;
    }

    public function getSecondLdapProvider()
    {
        if (empty($this->_secondLdapProvider)) {
            $this->initAdLdap();
        }
        return $this->_secondLdapProvider;
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
            $this->_ldapProvider = $ad;
        } catch (adLDAPException $e) {
            if(YII_DEBUG) {
                throw $e;
            }
            $this->error("Error connecting to LDAP Server", $e->getMessage());
            throw new LdapConfigurationErrorException($e->getMessage());
        }
        // Connect second LDAP
        if ($this->secondLdapConfig !== FALSE) {
            $ad2 = new Adldap();
            $ad2->addProvider($this->secondLdapConfig);
            try {
                $ad2->connect();
                $this->_secondLdapProvider = $ad2;
            } catch (adLDAPException $e) {
                $this->error("Error connecting to the second LDAP Server", $e);
                throw new LdapConfigurationErrorException($e->getMessage());
            }
        }
        parent::init();
    }

    public function events() {
        Event::on(LoginForm::class, LoginForm::EVENT_AFTER_VALIDATE, function (Event $event) {
            $this->initAdLdap();

            /* @var $form \Da\User\Form\LoginForm */
            $form = $event->sender;

            if (!$form->hasErrors()) {
                // Local login already succeeded, no need to try LDAP
                return;
            }

            /* @var $provider Provider */
            $provider = Yii::$app->usuarioLdap->ldapProvider;

            $username = $form->login;
            $password = $form->password;

            // If somehow username or password are empty, lets usuario handle it
            if (empty($username) || empty($password)) {
                $this->info("Either username or password was not specified");
                return;
            }

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            if (!$this->tryAuthentication($provider, $username, $password)) {
                $failed = true;
                if (is_array($this->otherOrganizationalUnits)) {
                    foreach ($this->otherOrganizationalUnits as $otherOrganizationalUnit) {
                        $prov = $provider->getProvider($otherOrganizationalUnit);
                        if ($this->tryAuthentication($prov, $username, $password)) {
                            $failed = false;
                            break;
                        }
                    }
                }
                if ($failed) {
                    $this->warning("Authentication failed");
                    // Failed.
                    return;
                }
            }

            // LDAP authentication successfully, from now on we have to manage what to do with the user based on the module configuration

            $username_inserted = $username;
            try {
                $ldap_user = $this->findLdapUser($username, self::$ldapAttrs , $provider);
            } catch (NoLdapUserException|MultipleUsersFoundException $e) {
                $this->error("Impossible to retrive LDAP user, even if authentication succeeded I must block login", $e);
                return false;
            }

            foreach (self::$ldapAttrs AS $key) {
                $username = $ldap_user->getAttribute($key, '0');
                if (!empty($username)) {
                    break;
                }
            }

            if (empty($username)) {
                $username = $username_inserted;
            }
            $user = User::find()->andWhere(['or',
                ['username' => $username],
                ['email' => $ldap_user->getEmail() ?:  uniqid('no_email_so_no_email_search_', true)]
            ])->one();
            if (empty($user)) {
                $this->info("User not found in the application database searching with $key $username or {$ldap_user->getEmail()}");
                if ($this->createLocalUsers) {
                    $this->info("The user will be created");
                    $user = Yii::createObject(User::class);
                    $user->username = $username;
                    $user->password = uniqid("", true);
                    // Gets the email from the ldap user
                    $user->email = $ldap_user->getEmail();
                    $user->source = UserSourceType::LDAP;
                    if (empty($user->email)) {
                        $user->email = NULL;
                    }
                    $user->confirmed_at = time();
                    $user->password_hash = 'x';
                    if (!$user->save()) {
                        $this->error("Error saving the new user in the database", $user->errors);
                        // FIXME handle save error
                        return;
                    }

                    // Gets the profile name of the user from the CN of the LDAP user
                    $profileClass = $this->getClassMap()->get(Profile::class);
                    $profile = $profileClass::findOne(['user_id' => $user->id]);
                    $profile->name = $ldap_user->getAttribute('cn', 0);
                    // Tries to save only if the name has been found
                    if ($profile->name && !$profile->save()) {
                        $this->error("Error saving the new profile in the database", $profile->errors);
                        // FIXME handle save error
                    }

                    if ($this->defaultRoles !== false) {
                        // FIXME this should be checked in init()
                        if (!is_array($this->defaultRoles)) {
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
                        $user = Yii::createObject(User::class);
                        $user->id = $this->defaultUserId;
                        $user->email = "default@user.com";
                        $user->confirmed_at = time();
                        if (!$user->save()) {
                            $this->error("Error creating the default user", $user->errors);
                            //FIXME handle save error
                            return;
                        }
                        if ($this->defaultRoles !== false) {
                            // FIXME this should be checked in init()
                            if (!is_array($this->defaultRoles)) {
                                throw new ErrorException('defaultRoles parameter must be an array');
                            }
                            $this->assignRoles($user->id);
                        }
                    }

                    $user->username = $username;
                }
            }

            // Now I have a valid user which passed LDAP authentication, we remove any error that may stop the login based on previous local authentication
            $form->clearErrors('password');
            $clIdentityUser = $this->make(User::class);

            $userIdentity = $clIdentityUser::findIdentity($user->id);
            $form->setUser($userIdentity);

            $this->info("The user '{$user->username}' has successfully logged in via LDAP");
        });

        Event::on(RecoveryController::class, FormEvent::EVENT_BEFORE_REQUEST, function (FormEvent $event) {
            $this->initAdLdap();
            /**
             * After a user recovery request is sent, it checks if the email given is one of a LDAP user.
             * If the user is found and the parameter `allowPasswordRecovery` is set to FALSE, it redirect
             * to the url specified in `passwordRecoveryRedirect`
             */
            $form = $event->getForm();
            $email = $form->email;
            try {
                $ldapUser = $this->findLdapUser($email, 'mail', Yii::$app->usuarioLdap->ldapProvider);
            } catch (NoLdapUserException $e) {
                $this->info("User $email not found");
                return;
            }
            if (!is_null($ldapUser) && !$this->allowPasswordRecovery) {
                Yii::$app->controller->redirect($this->passwordRecoveryRedirect)->send();
                Yii::$app->end();
            }
        });

        Event::on(SettingsForm::class, SettingsForm::EVENT_AFTER_VALIDATE, function (Event $event) {
            $this->initAdLdap();

            /* @var $form \Da\User\Form\SettingsForm */
            $form = $event->sender;

            if (!$form->hasErrors() && empty($form->current_password)) {
                // Local login already succeeded, no need to try LDAP
                return;
            }

            /* @var $provider Provider */
            $provider = Yii::$app->usuarioLdap->ldapProvider;

            // https://adldap2.github.io/Adldap2/#/setup?id=authenticating
            if (!$this->tryAuthentication($provider, $form->getUser()->username, $form->current_password)) {
                $failed = TRUE;
                if($this->otherOrganizationalUnits) {
                    foreach ($this->otherOrganizationalUnits as $otherOrganizationalUnit) {
                        $prov = $provider->getProvider($otherOrganizationalUnit);
                        if($this->tryAuthentication($prov, $form->getUser()->username, $form->current_password)) {
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

            // Now I have a valid user which passed LDAP authentication, we remove any error on the current password
            // based on previous local authentication so that they can still save
            $form->clearErrors('current_password');
        });
        if ($this->syncUsersToLdap !== true) {
            // If I don't have to sync the local users to LDAP I don't need next events
            return;
        }

        Event::on(SecurityController::class, FormEvent::EVENT_AFTER_LOGIN, function (FormEvent $event) {
            $this->initAdLdap();
            /**
             * After a successful login if no LDAP user is found I create it.
             * Is the only point where I can have the user password in clear for existing users
             * and sync them to LDAP
             * @var LoginForm $form
             */
            /** @var \Da\User\Form\LoginForm $form */
            $form = $event->getForm();

            $user = $form->getUser();
            try {
                $ldapUser = $this->findLdapUser($user->username, 'cn');
                $ldapEmail = $ldapUser->getEmail();
                // If the email address of the user in the application doesn't correspond with the one on the LDAP server
                // we override the local one and display a
                if(!empty($ldapEmail) && $ldapEmail !== $user->email) {
                    $oldEmail = $user->email;
                    $user->email = $ldapEmail;
                    if (!$user->save()) {
                        $this->error("Could not sync local email with remote one", $user->errors);
                    } else if(is_a(Yii::$app, WebApplication::class)) {
                        Yii::$app->session->addFlash('warning', Yii::t('usuarioLdap',
                            'Your local user email ({oldEmail}) has been automatically updated with the one on the remote server ({newEmail})',
                            [
                                'oldEmail' => $oldEmail,
                                'newEmail' => $user->email,
                            ]
                        ));
                    }
                }
            } catch (NoLdapUserException $e) {
                $user->password = $form->password;
                $this->info('User information', $user);
                $this->createLdapUser($user);
            }
        }, null, false);

        Event::on(AdminController::class, UserEvent::EVENT_AFTER_CREATE, function (UserEvent $event) {
            $this->initAdLdap();
            $user = $event->getUser();
            try {
                // We'll create the user on LDAP only if it doesn't already exist on LDAP
                // TODO: it'd be better if findLdapUser would return null
                try {
                    $this->findLdapUser($user->username, 'cn');
                } catch (NoLdapUserException $exception) {
                    $this->createLdapUser($user);
                }
            } catch (LdapUserException $e) {
                // Probably the user already exists on LDAP
                // TODO:
                // I can arrive here if:
                // * LDAP access is enabled with local user creation and local users sync is enabled with the same LDAP
                // * local users sync is enabled with an already populated LDAP and somebody tries to create a user with an existing username in LDAP
                // None of the presented cases at the moment is part of our specifications
            }
        }, null, false);

        // Write user to LDAP after confirmation (high-priority event/do not append)
        Event::on(RegistrationController::class, UserEvent::EVENT_AFTER_CONFIRMATION, function (UserEvent $event) {
            $this->info(UserEvent::EVENT_AFTER_CONFIRMATION);
            $user = $event->getUser();
            $this->createLdapUser($user);
        }, null, false);


        Event::on(AdminController::class, UserEvent::EVENT_AFTER_ACCOUNT_UPDATE, function (UserEvent $event) {
            $this->initAdLdap();
            $user = $event->getUser();
            $this->updateLdapUser($user);
        });
        Event::on(SettingsController::class, UserEvent::EVENT_AFTER_ACCOUNT_UPDATE, function (UserEvent $event) {
            $this->initAdLdap();
            $user = $event->getUser();
            $this->updateLdapUser($user);
        });
        Event::on(RecoveryController::class, ResetPasswordEvent::EVENT_AFTER_RESET, function (ResetPasswordEvent $event) {
            $this->initAdLdap();
            $token = $event->getToken();
            if (!$token) {
                $this->error('Token does not exist', $token);
                return;
            }
            $user = $token->user;
            try {
                /* @var $ldapUser AdldapUser */
                $ldapUser = $this->findLdapUser($user->username, 'cn');
            } catch (NoLdapUserException $e) {
                // Unable to find the user in ldap, if I have the password in cleare I create it
                // these case typically happens when the sync is enabled and we already have users
                if (!empty($user->password)) {
                    $this->createLdapUser($user);
                    Event::trigger(UsuarioLdapComponent::class, LdapEvent::EVENT_AFTER_INITAL_PASSWORD_RESET);
                }
                return;
            }
            // If clear password is specified I update it also in LDAP
            $ldapUser->setPassword($user->password);

            if (!$ldapUser->save()) {
                throw new ErrorException("Impossible to modify the LDAP user");
            }
            Event::trigger(UsuarioLdapComponent::class, LdapEvent::EVENT_AFTER_PASSWORD_RESET);
        }, null, false);

        // Delete LDAP user (run as last event)
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
        // We have to use the AFTER_VALIDATE because AuthManager doesn't launch any event when assigning or revoking
        // a role to/from a user
        Event::on(Assignment::class, Assignment::EVENT_AFTER_VALIDATE, function (Event $event) {
            /** @var Assignment $model */
            $model = $event->sender;
            // Model validate has failed
            if($model->hasErrors()) {
                return;
            }

            $this->initAdLdap();

            if (!is_array($model->items)) {
                $model->items = [];
            }

            /** @var User $user */
            $user = $this->make(UserQuery::class)->where(['id' => $model->user_id])->one();

            try {
                $ldapUser = $this->findLdapUser(
                    $user->username,
                    self::$ldapAttrs
                );
            } catch (NoLdapUserException $e) {
                // Not an LDAP user
                return;
            }
            $assignedItems = $this->getAuthManager()->getItemsByUser($model->user_id);
            $assignedItemsNames = array_keys($assignedItems);

            foreach (array_diff($assignedItemsNames, $model->items) as $item) {
                // Getting the groups for the given item
                $groups = ArrayHelper::getValue($this->rolesGroupsMap, $item, []);
                // Casting the groups to array since they could be a single group set as a string
                foreach ((array)$groups as $group) {
                    $ldapUser->removeGroup($group);
                }
            }

            foreach (array_diff($model->items, $assignedItemsNames) as $item) {
                // Getting the groups for the given item
                $groups = ArrayHelper::getValue($this->rolesGroupsMap, $item, []);
                // Casting the groups to array since they could be a single group set as a string
                foreach ((array)$groups as $group) {
                    $ldapUser->addGroup($group);
                }
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

    private function tryAuthentication($provider, $username, $password)
    {
        $this->info("Trying authentication for {$username} with provider", $provider->getConnection()->getName());
        // Tries to authenticate the user with the standard configuration
        if ($provider->auth()->attempt($username, $password)) {
            $this->info("User successfully authenticated");
            return true;
        }

        $this->info("Default authentication didn't work, it will be tried again with another attribute");

        // Finds the user first searching the username in ldap field configured
        try {
            $user = $this->findLdapUser($username, self::$ldapAttrs, $provider);
        } catch (NoLdapUserException $e) {
            $this->warning("Couldn't find the user using another attribute");
            return false;
        }

        // Gets the user authentication attribute from the distinguished name
        $dn = $user->getAttribute($provider->getSchema()->distinguishedName(), 0);
        $this->info($dn);

        try {
            if ($provider->auth()->attempt($dn, $password)) {
                $this->info("User successfully authenticated with \$dn");
                return true;
            }
        } catch (\Exception $e) {
            $this->error($e->getMessage());
        }

        // Since an account can be matched by several attributes I take the one used in the dn for doing the bind
        $dnCommas = explode(",", $dn);
        list($userAuthKey,$userAuth) = explode("=", array_shift($dnCommas));

        $config = $this->ldapConfig;
        $config['account_prefix'] = $userAuthKey . "=";
        $config['account_suffix'] = "," . implode(",", $dnCommas);
        $config['base_dn'] = implode(",", $dnCommas);
        $this->info($userAuth);

        try {
            // The provider configuration needs to be reset with the new account_prefix
            $provider->setConfiguration($config);
            $provider->connect();
            // Not sure the case with $dn covers all the cases, for now we keep this here
            if ($provider->auth()->attempt($userAuth, $password)) {
                $this->info("User successfully authenticated with \$userAuth");
                return true;
            }
            $provider->setConfiguration($this->ldapConfig);
            $provider->connect();
        } catch (\Exception $e) {
            $this->error($e->getMessage());
        }
        return false;
    }

    /**
     * @param $username
     * @param string|string[] $keys
     * @param string $ldapProvider
     * @return AdldapUser
     * @throws MultipleUsersFoundException
     * @throws \yetopen\usuarioLdap\NoLdapUserException
     */
    public function findLdapUser ($username, $keys = null, $provider = null) {
        if ($keys === null) {
            $keys = self::$ldapAttrs;
        }
        if (is_null($provider)) {
            $provider = Yii::$app->usuarioLdap->secondLdapProvider;
        }
        if (!empty($this->ldapUser)) {
            $this->info("User already found");
            return $this->ldapUser;
        }

        if (!is_array($keys)) $keys = [$keys];
        foreach ($keys as $key) {
            $ldapUser = $provider->search()
                ->where($this->userIdentificationLdapAttribute ?: $key, '=', $username)
                ->first();
            if (!empty($ldapUser)) {
                $this->info("Found user with attribute `$key`");
                break;
            }
        }

        if (empty($ldapUser)) {
            $ldapUser = $provider->search()->find($username);
            if (!empty($ldapUser)) {
                $this->info("Found user with generic find");
            }
        }

        if (empty($ldapUser)) {
            throw new NoLdapUserException("LDAP user $username not found");
        }

        if (is_array($ldapUser)) {
            throw new MultipleUsersFoundException();
        }

        if (get_class($ldapUser) !== AdldapUser::class) {
            throw new NoLdapUserException("The search for the user returned an instance of the class " . get_class($ldapUser));
        }
        $this->ldapUser = $ldapUser;
        return $this->ldapUser;

    }

    /**
     * @param $username
     * @param null $provider
     * @param int $limit
     * @return Collection
     */
    public function findLdapUsers($username, $provider = null, $limit = 20)
    {
        /* @var $provider Provider */
        if (is_null($provider)) {
            $provider = Yii::$app->usuarioLdap->secondLdapProvider;
        }

        $ldapUsers = $provider->search()->limit($limit)->find([$username]);
        if (!empty($ldapUsers)) {
            $this->info("Found users with attributes `$username`");
        }

        return $ldapUsers;
    }

    /**
     * @param User $user
     * @throws ErrorException
     */
    private function createLdapUser ($user) {
        /** @var AdldapUser $ldapUser */
        $ldapUser = Yii::$app->usuarioLdap->secondLdapProvider->make()->user([
            'cn' => $user->username,
        ]);

        // set user dn
        $dn = "cn=$user->username" . $this->ldapConfig['account_suffix'];
        $ldapUser->setDn($dn);

        // Set LDAP user attributes from local user if changed
        $ldapUser->fill(ArrayHelper::toArray($user, [
            get_class($user) => static::$mapUserARtoLDAPattr,
        ]));

        $ldapUser->setPassword($user->password);

        // If requested we'll set the user account control
        if(method_exists($ldapUser, 'setUserAccountControl') && $this->defaultUserAccountControl !== false) {
            $ldapUser->setUserAccountControl($this->defaultUserAccountControl);
        }

        if (!$ldapUser->save()) {
            throw new LdapUserException("Impossible to create the LDAP user");
        }

        // If set on the module configuration, adding the newly created user to the groups corresponding to Yii2 roles.
        foreach ($this->rolesGroupsMap as $role => $groups) {
            // User must be directly assigned to the role to be added to the group
            if($user->hasRole($role)) {
                // Groups can be either a string or an array, casting it to array
                foreach ((array)$groups as $group) {
                    if(!$ldapUser->addGroup($group)) {
                        $this->error("Could not add user {$user->username} to LDAP group {$group}");
                    }
                }
            }
        }
    }

    /**
     * @param User $user
     * @return void
     * @throws ErrorException
     * @throws MultipleUsersFoundException
     */
    private function updateLdapUser($user)
    {
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

        // Set LDAP user attributes from local user. In case the attribute has not been changed it is handled directly
        // by AdLdap plugin, this way any misalignment can be handled by simply saving the user.
        $ldapUser->fill(ArrayHelper::toArray($user, [
            get_class($user) => static::$mapUserARtoLDAPattr,
        ]));

        // If the clear password is set, it means it has been changed we need to update it in LDAP also
        if (!empty($user->password)) {
            $ldapUser->setPassword($user->password);
        }

        if (!$ldapUser->save()) {
            throw new ErrorException("Impossible to modify the LDAP user");
        }

        if ($username != $user->username) {
            /** @var Provider $provider */
            $provider = Yii::$app->usuarioLdap->secondLdapProvider;
            $dn = $provider->getSchema()->commonName();
            // If username is changed the procedure to change the cn in LDAP is the following
            if (!$ldapUser->rename("$dn={$user->username}")) {
                throw new ErrorException("Impossible to rename the LDAP user");
            }
        }

        $user->password_hash = 'x';
        $user->save();
    }

    /**
     * @param integer $userId
     * @throws ErrorException
     * @throws RoleNotFoundException
     */
    private function assignRoles($userId)
    {
        $auth = Yii::$app->authManager;
        foreach ($this->defaultRoles as $roleName) {
            if (!is_string($roleName)) {
                throw new ErrorException('The role name must be a string');
            }
            if (!($role = $auth->getRole($roleName))) {
                throw new RoleNotFoundException($roleName);
            }

            $auth->assign($role, $userId);
        }
    }

    /**
     * Checks the plugin configuration params
     *
     * @throws LdapConfigurationErrorException
     */
    private function checkLdapConfiguration()
    {
        if (!isset($this->ldapConfig)) {
            throw new LdapConfigurationErrorException('ldapConfig must be specified');
        }
        if (!isset($this->ldapConfig['schema'])) {
            throw new LdapConfigurationErrorException('schema must be specified');
        }
        if ($this->ldapConfig['schema'] === OpenLDAP::class) {
            $this->checkOpenLdapConfiguration();
        }
        if ($this->allowPasswordRecovery === false && is_null($this->passwordRecoveryRedirect)) {
            throw new LdapConfigurationErrorException('passwordRecoveryRedirect must be specified if allowPasswordRecovery is set to FALSE');
        }
    }

    /**
     * Checks the plugin configuration params when the schema is set as OpenLDAP
     *
     * @throws LdapConfigurationErrorException
     */
    private function checkOpenLdapConfiguration()
    {
        if (!isset($this->ldapConfig['account_suffix'])) {
            throw new LdapConfigurationErrorException(OpenLDAP::class . ' requires an account suffix');
        }
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function error($message, $object = null)
    {
        $this->log('error', $message, $object);
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function warning($message, $object = null)
    {
        $this->log('warning', $message, $object);
    }

    /**
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */
    private function info($message, $object = null)
    {
        $this->log('info', $message, $object);
    }

    /**
     * @param $level string
     * @param $message string
     * @param null $object If specified it will be dumped and concatenated to the message after ": "
     */

    private function log($level, $message, $object)
    {
        if (!empty($object)) {
            $message .= ": " . VarDumper::dumpAsString($object);
        }
        Yii::$level($message, $this->logCategory);
    }

    /**
     * @param string $username
     *
     * @return Model|null
     */
    public function userByUsername(string $username): ?Model
    {
        return $this->ldapProvider->search()->whereEquals('cn', $username)->first();
    }

    /**
     * @param string $username
     *
     * @return bool
     */
    public function userIsLdapUser(string $username): bool
    {
        return $this->userByUsername($username) !== null;
    }

    public function updateUserAttribute(string $username, string $attributeName, $newValue): bool
    {
        $ldapUser = $this->userByUsername($username);
        if ($ldapUser) {
            $ldapUser->setAttribute($attributeName, $newValue);
            return $ldapUser->save();
        }
        return false;
    }

}