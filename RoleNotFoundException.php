<?php

namespace yetopen\usuarioLdap;

use Exception;

class RoleNotFoundException extends Exception
{
    /**
     * RoleNotFoundException constructor.
     * @param string $roleName
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct($roleName, $code = 0, Throwable $previous = null)
    {
        $message = "$roleName role was not found";
        parent::__construct($message, $code, $previous);
    }
}
