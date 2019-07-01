<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

class AuthResponseFactory implements AuthResponseFactoryInterface
{
    public function createFromClaims(array $claims): AuthResponseInterface
    {
        return AuthResponse::fromParams($claims);
    }
}
