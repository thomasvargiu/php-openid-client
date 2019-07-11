<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Client\Metadata;

interface MetadataFactoryInterface
{
    public function fromArray(array $metadata): ClientMetadataInterface;
}
