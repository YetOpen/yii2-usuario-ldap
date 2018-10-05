<?php

class RoleNotFoundException extends \yii\base\Exception
{
    /**
     * RoleNotFoundException constructor.
     * @param string $roleName
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(string $roleName = "", int $code = 0, Throwable $previous = null)
    {
        $message = "$message role was not found";
        parent::__construct($message, $code, $previous);
    }
}