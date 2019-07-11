<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

class TokenSetFactory implements TokenSetFactoryInterface
{
    public function fromArray(array $array): TokenSetInterface
    {
        return TokenSet::fromParams($array);
    }
}
