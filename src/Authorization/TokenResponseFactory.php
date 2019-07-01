<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

class TokenResponseFactory implements TokenResponseFactoryInterface
{
    public function createFromClaims(array $claims): TokenResponseInterface
    {
        return TokenResponse::fromParams($claims);
    }
}
