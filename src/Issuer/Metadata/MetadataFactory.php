<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata;

use TMV\OpenIdClient\Issuer\Metadata\Provider\DiscoveryProvider;
use TMV\OpenIdClient\Issuer\Metadata\Provider\DiscoveryProviderInterface;
use TMV\OpenIdClient\Issuer\Metadata\Provider\WebFingerProvider;
use TMV\OpenIdClient\Issuer\Metadata\Provider\WebFingerProviderInterface;

final class MetadataFactory implements MetadataFactoryInterface
{
    /** @var DiscoveryProviderInterface */
    private $discoveryProvider;

    /** @var WebFingerProviderInterface */
    private $webFingerProvider;

    /**
     * Provider constructor.
     *
     * @param null|DiscoveryProviderInterface $discoveryProvider
     * @param null|WebFingerProviderInterface $webFingerProvider
     */
    public function __construct(
        ?DiscoveryProviderInterface $discoveryProvider = null,
        ?WebFingerProviderInterface $webFingerProvider = null
    ) {
        $this->discoveryProvider = $discoveryProvider ?: new DiscoveryProvider();
        $this->webFingerProvider = $webFingerProvider ?: new WebFingerProvider();
    }

    public function discovery(string $uri): IssuerMetadataInterface
    {
        $metadata = $this->discoveryProvider->discovery($uri);

        return $this->fromArray($metadata);
    }

    public function webFinger(string $resource): IssuerMetadataInterface
    {
        $metadata = $this->webFingerProvider->fetch($resource);

        return $this->fromArray($metadata);
    }

    public function fromArray(array $metadata): IssuerMetadataInterface
    {
        return IssuerMetadata::fromArray($metadata);
    }
}
