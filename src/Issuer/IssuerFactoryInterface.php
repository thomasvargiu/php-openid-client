<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer;

interface IssuerFactoryInterface
{
    public function fromUri(string $uri): IssuerInterface;

    public function fromWebFinger(string $resource): IssuerInterface;
}
