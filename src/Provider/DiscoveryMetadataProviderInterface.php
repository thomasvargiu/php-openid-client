<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

interface DiscoveryMetadataProviderInterface
{
    public function discovery(string $uri): array;
}
