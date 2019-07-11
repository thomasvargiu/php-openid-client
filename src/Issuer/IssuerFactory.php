<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Jose\Component\KeyManagement\JKUFactory;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;
use TMV\OpenIdClient\Issuer\Metadata\MetadataFactory;
use TMV\OpenIdClient\Issuer\Metadata\MetadataFactoryInterface;

class IssuerFactory implements IssuerFactoryInterface
{
    /** @var MetadataFactoryInterface */
    private $metadataFactory;

    /** @var JKUFactory */
    private $JKUFactory;

    public function __construct(?MetadataFactoryInterface $metadataFactory = null, ?JKUFactory $JKUFactory = null)
    {
        $this->metadataFactory = $metadataFactory ?: new MetadataFactory();
        $this->JKUFactory = $JKUFactory ?: new JKUFactory(
            Psr18ClientDiscovery::find(),
            Psr17FactoryDiscovery::findRequestFactory()
        );
    }

    public function fromUri(string $uri): IssuerInterface
    {
        $metadata = $this->metadataFactory->discovery($uri);

        return $this->createIssuer($metadata);
    }

    public function fromWebFinger(string $resource): IssuerInterface
    {
        $metadata = $this->metadataFactory->webFinger($resource);

        return $this->createIssuer($metadata);
    }

    private function createIssuer(IssuerMetadataInterface $metadata): IssuerInterface
    {
        $jwks = $this->JKUFactory->loadFromUrl($metadata->getJwksUri());

        return new Issuer($metadata, $jwks, $this->JKUFactory);
    }
}
