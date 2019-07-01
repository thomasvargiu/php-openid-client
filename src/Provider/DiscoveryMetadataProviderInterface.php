<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

use TMV\OpenIdClient\Model\IssuerMetadataInterface;

interface DiscoveryMetadataProviderInterface
{
    public function discovery(string $uri): IssuerMetadataInterface;
}
