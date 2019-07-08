<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use TMV\OpenIdClient\ClientInterface;

interface ResponseTokenVerifierInterface
{
    public function validate(ClientInterface $client, string $token): array;
}
