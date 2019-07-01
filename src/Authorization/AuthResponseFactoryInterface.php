<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

interface AuthResponseFactoryInterface
{
    public function createFromClaims(array $claims): AuthResponseInterface;
}
