<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Issuer;
use TMV\OpenIdClient\IssuerFactory;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProviderInterface;

class IssuerFactoryTest extends TestCase
{
    public function testFromUri(): void
    {
        $discovery = $this->prophesize(DiscoveryMetadataProviderInterface::class);
        $JKUFactory = $this->prophesize(JKUFactory::class);

        $uri = 'https://example.com/.well-known/openid-configuration';

        $discovery->discovery($uri)->willReturn([
            'issuer' => 'foo',
            'authorization_endpoint' => 'https://issuer.com/auth',
            'jwks_uri' => 'https://issuer.com/jwks',
        ]);

        $jwks = $this->prophesize(JWKSet::class);
        $JKUFactory->loadFromUrl('https://issuer.com/jwks')
            ->willReturn($jwks->reveal());

        $factory = new IssuerFactory($discovery->reveal(), $JKUFactory->reveal());

        $result = $factory->fromUri($uri);

        $this->assertInstanceOf(Issuer::class, $result);
        $this->assertSame('foo', $result->getMetadata()->getIssuer());
    }

    public function testFromWebFinger(): void
    {
        $discovery = $this->prophesize(DiscoveryMetadataProviderInterface::class);
        $JKUFactory = $this->prophesize(JKUFactory::class);

        $resource = 'https://example.com/';

        $discovery->webfinger($resource)->willReturn([
            'issuer' => 'foo',
            'authorization_endpoint' => 'https://issuer.com/auth',
            'jwks_uri' => 'https://issuer.com/jwks',
        ]);

        $jwks = $this->prophesize(JWKSet::class);
        $JKUFactory->loadFromUrl('https://issuer.com/jwks')
            ->willReturn($jwks->reveal());

        $factory = new IssuerFactory($discovery->reveal(), $JKUFactory->reveal());

        $result = $factory->fromWebFinger($resource);

        $this->assertInstanceOf(Issuer::class, $result);
        $this->assertSame('foo', $result->getMetadata()->getIssuer());
    }
}
