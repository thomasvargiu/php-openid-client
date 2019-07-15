<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Issuer;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Issuer\Issuer;
use TMV\OpenIdClient\Issuer\IssuerFactory;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;
use TMV\OpenIdClient\Issuer\Metadata\MetadataFactoryInterface;

class IssuerFactoryTest extends TestCase
{
    public function testMinimalConstructor(): void
    {
        $factory = new IssuerFactory();

        self::assertInstanceOf(IssuerFactory::class, $factory);
    }

    public function testFromUri(): void
    {
        $uri = 'https://example.com/.well-known/openid-configuration';

        $metadataFactory = $this->prophesize(MetadataFactoryInterface::class);
        $JKUFactory = $this->prophesize(JKUFactory::class);

        $metadata = $this->prophesize(IssuerMetadataInterface::class);
        $metadata->getJwksUri()->willReturn('https://issuer.com/jwks');
        $metadataFactory->discovery($uri)->willReturn($metadata->reveal());

        $jwks = $this->prophesize(JWKSet::class);
        $JKUFactory->loadFromUrl('https://issuer.com/jwks')
            ->willReturn($jwks->reveal());

        $factory = new IssuerFactory($metadataFactory->reveal(), $JKUFactory->reveal());

        $result = $factory->fromUri($uri);

        static::assertInstanceOf(Issuer::class, $result);
        static::assertSame($metadata->reveal(), $result->getMetadata());
    }

    public function testFromWebFinger(): void
    {
        $resource = 'https://example.com/';

        $metadataFactory = $this->prophesize(MetadataFactoryInterface::class);
        $JKUFactory = $this->prophesize(JKUFactory::class);

        $metadata = $this->prophesize(IssuerMetadataInterface::class);
        $metadata->getJwksUri()->willReturn('https://issuer.com/jwks');
        $metadataFactory->webFinger($resource)->willReturn($metadata->reveal());

        $jwks = $this->prophesize(JWKSet::class);
        $JKUFactory->loadFromUrl('https://issuer.com/jwks')
            ->willReturn($jwks->reveal());

        $factory = new IssuerFactory($metadataFactory->reveal(), $JKUFactory->reveal());

        $result = $factory->fromWebFinger($resource);

        static::assertInstanceOf(Issuer::class, $result);
        static::assertSame($metadata->reveal(), $result->getMetadata());
    }
}
