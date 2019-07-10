<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;

class Issuer implements IssuerInterface
{
    /** @var IssuerMetadataInterface */
    private $metadata;

    /** @var JWKSet */
    private $jwks;

    /** @var JKUFactory */
    private $JKUFactory;

    /**
     * Issuer constructor.
     *
     * @param IssuerMetadataInterface $metadata
     * @param JWKSet $jwks
     * @param JKUFactory|null $JKUFactory
     */
    public function __construct(
        IssuerMetadataInterface $metadata,
        JWKSet $jwks,
        ?JKUFactory $JKUFactory = null
    ) {
        $this->metadata = $metadata;
        $this->jwks = $jwks;
        $this->JKUFactory = $JKUFactory ?: new JKUFactory(
            Psr18ClientDiscovery::find(),
            Psr17FactoryDiscovery::findRequestFactory()
        );
    }

    public function getMetadata(): IssuerMetadataInterface
    {
        return $this->metadata;
    }

    /**
     * @return JWKSet
     */
    public function getJwks(): JWKSet
    {
        return $this->jwks;
    }

    public function updateJwks(): void
    {
        $this->jwks = $this->JKUFactory->loadFromUrl($this->metadata->getJwksUri());
    }
}
