<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

interface IssuerMetadataProviderInterface
{
    public function webfinger(string $resource): array;

    public function discovery(string $uri): array;
}
