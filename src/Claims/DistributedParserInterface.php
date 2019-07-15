<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Claims;

use TMV\OpenIdClient\Client\ClientInterface;

interface DistributedParserInterface
{
    public function fetch(ClientInterface $client, array $claims, array $accessTokens = []): array;
}
