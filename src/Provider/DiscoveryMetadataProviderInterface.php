<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

interface DiscoveryMetadataProviderInterface
{
    public function webfinger(string $resource): array;

    public function discovery(string $uri): array;
}
