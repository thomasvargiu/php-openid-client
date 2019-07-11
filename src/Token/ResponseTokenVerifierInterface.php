<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use TMV\OpenIdClient\Client\ClientInterface;

interface ResponseTokenVerifierInterface
{
    public function validate(ClientInterface $client, string $token): array;
}
