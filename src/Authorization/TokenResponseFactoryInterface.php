<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

interface TokenResponseFactoryInterface
{
    public function createFromClaims(array $claims): TokenResponseInterface;
}
