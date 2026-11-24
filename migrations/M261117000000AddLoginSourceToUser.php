<?php

namespace yetopen\usuarioLdap\migrations;

use yii\db\Migration;

/**
 * Adds `user.login_source`: which check accepted the password of the user's last successful login
 * (`local` or `ldap`). It is written by {@see \yetopen\usuarioLdap\UsuarioLdapComponent} on every successful
 * password validation and read when `allowPasswordChange` is FALSE. Existing users stay NULL (unknown, treated as
 * `ldap`) until their next login: there is nothing in the table that tells LDAP users apart.
 */
class M261117000000AddLoginSourceToUser extends Migration
{
    const TABLE = '{{%user}}';
    const COLUMN = 'login_source';

    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        if ($this->db->getTableSchema(self::TABLE, true)->getColumn(self::COLUMN) !== null) {
            return;
        }
        $this->addColumn(
            self::TABLE,
            self::COLUMN,
            $this->string(16)->null()->comment(
                'Check that accepted the password at the last successful login: local or ldap. NULL = unknown, treated as ldap'
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        if ($this->db->getTableSchema(self::TABLE, true)->getColumn(self::COLUMN) === null) {
            return;
        }
        $this->dropColumn(self::TABLE, self::COLUMN);
    }
}
