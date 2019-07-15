<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata\Provider;

interface DiscoveryProviderInterface
{
    public function discovery(string $url): array;
}
