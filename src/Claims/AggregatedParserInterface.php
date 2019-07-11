<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Claims;

use TMV\OpenIdClient\Client\ClientInterface;

interface AggregatedParserInterface
{
    public function unpack(ClientInterface $client, array $claims): array;
}
