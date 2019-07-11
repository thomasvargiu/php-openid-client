<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Client;

use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\Client\Client;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;

class ClientTest extends TestCase
{
    public function testMinimalConstructor(): void
    {
        $issuer = $this->prophesize(IssuerInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);

        $client = new Client(
            $issuer->reveal(),
            $metadata->reveal()
        );

        static::assertSame($issuer->reveal(), $client->getIssuer());
        static::assertSame($metadata->reveal(), $client->getMetadata());
        static::assertInstanceOf(JWKSet::class, $client->getJwks());
        static::assertInstanceOf(AuthMethodFactoryInterface::class, $client->getAuthMethodFactory());
    }

    public function testWithFullConstructor(): void
    {
        $issuer = $this->prophesize(IssuerInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $jwks = $this->prophesize(JWKSet::class);
        $authMethodFactory = $this->prophesize(AuthMethodFactoryInterface::class);

        $client = new Client(
            $issuer->reveal(),
            $metadata->reveal(),
            $jwks->reveal(),
            $authMethodFactory->reveal()
        );

        static::assertSame($issuer->reveal(), $client->getIssuer());
        static::assertSame($metadata->reveal(), $client->getMetadata());
        static::assertSame($jwks->reveal(), $client->getJwks());
        static::assertSame($authMethodFactory->reveal(), $client->getAuthMethodFactory());
    }
}
