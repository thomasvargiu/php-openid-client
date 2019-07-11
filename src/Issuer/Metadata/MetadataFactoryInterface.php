<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata;

interface MetadataFactoryInterface
{
    public function discovery(string $uri): IssuerMetadataInterface;

    public function webFinger(string $resource): IssuerMetadataInterface;

    public function fromArray(array $metadata): IssuerMetadataInterface;
}
