<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

interface TokenSetFactoryInterface
{
    public function fromArray(array $array): TokenSetInterface;
}
