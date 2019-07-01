<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

interface AuthMethodFactoryInterface
{
    public function create(string $authMethod): AuthMethodInterface;
}
