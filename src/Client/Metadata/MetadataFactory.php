<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Client\Metadata;

final class MetadataFactory implements MetadataFactoryInterface
{
    public function fromArray(array $metadata): ClientMetadataInterface
    {
        return ClientMetadata::fromArray($metadata);
    }
}
