<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use TMV\OpenIdClient\Client\ClientInterface;

interface TokenDecrypterInterface
{
    public function decryptToken(ClientInterface $client, string $token, string $use = 'id_token'): string;
}
