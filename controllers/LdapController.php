<?php

namespace yetopen\usuarioLdap\controllers;

use Adldap\Models\Contact;
use Adldap\Models\User;
use Da\User\Filter\AccessRuleFilter;
use Da\User\Model\User as UsuarioUser;
use yetopen\helpers\controllers\YOController;
use yetopen\usuarioLdap\UsuarioLdapComponent;
use Yii;
use yii\filters\AccessControl;
use yii\web\Response;

class LdapController extends YOController
{

    public function behaviors()
    {
        return [
            'access' => [
                'class' => AccessControl::class,
                'ruleConfig' => [
                    'class' => AccessRuleFilter::class,
                ],
                'rules' => [
                    [
                        'allow' => true,
                        'roles' => ['admin'],
                    ],
                ],
            ],
        ];
    }

    public function actionSearch($q) {
        Yii::$app->response->format = Response::FORMAT_JSON;
        /** @var UsuarioLdapComponent $ldapComponent */
        $ldapComponent = Yii::$app->usuarioLdap;
        $ldapUsers = $ldapComponent->findLdapUsers($q);
        $output = [];
        foreach ($ldapUsers as $ldapUser) {
            /** @var User|Contact $ldapUser */
            $userData = [];
            $value = is_a(User::class, $ldapUser) ? $ldapUser->getAuthIdentifier() : $ldapUser->getEmail();
            $userData['value'] = $value;
            $userData['label'] = $ldapUser->getFirstName() . ' ' . $ldapUser->getLastName() . ' - ' . $ldapUser->getEmail();
            $userData['q'] = $q;
            if(empty($value)) {
                // User has neither uid nor email, showing it with note that it has no mail
                $userData['value'] = UsuarioUser::LDAP_INVALID_USER;
                $userData['label'] = $userData['label'] . Yii::t('usuario', 'Invalid LDAP user');
            }
            $output[] = $userData;
        }
        return $output;
    }

}