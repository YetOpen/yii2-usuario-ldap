<?php

namespace yetopen\usuarioLdap\controllers;

use Da\User\Filter\AccessRuleFilter;
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
        foreach ($ldapUsers as $d) {
            if(!empty($d->mail)) {
                $output[] = [
                    'value' => $d->mail[0],
                    'username' => $d->samaccountname[0]
                ];
            }
        }
        return $output;
    }

}