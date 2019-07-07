<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Jose\Component\KeyManagement\JKUFactory;
use TMV\OpenIdClient\Model\IssuerMetadata;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProvider;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProviderInterface;

class IssuerFactory
{
    /** @var DiscoveryMetadataProviderInterface */
    private $discovery;

    /** @var JKUFactory */
    private $JKUFactory;

    /**
     * IssuerFactory constructor.
     *
     * @param null|DiscoveryMetadataProviderInterface $discovery
     * @param null|JKUFactory $JKUFactory
     */
    public function __construct(?DiscoveryMetadataProviderInterface $discovery = null, ?JKUFactory $JKUFactory = null)
    {
        $this->discovery = $discovery ?: new DiscoveryMetadataProvider();
        $this->JKUFactory = $JKUFactory ?: new JKUFactory(
            Psr18ClientDiscovery::find(),
            Psr17FactoryDiscovery::findRequestFactory()
        );
    }

    public function fromUri(string $uri): IssuerInterface
    {
        $metadata = IssuerMetadata::fromClaims($this->discovery->discovery($uri));
        $jwks = $this->JKUFactory->loadFromUrl($metadata->getJwksUri());

        return new Issuer($metadata, $jwks);
    }
}
