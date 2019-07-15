<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Issuer;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Issuer\Issuer;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;

class IssuerTest extends TestCase
{
    public function testMinimalConstructor(): void
    {
        $metadata = $this->prophesize(IssuerMetadataInterface::class);
        $jwks = $this->prophesize(JWKSet::class);

        $issuer = new Issuer(
            $metadata->reveal(),
            $jwks->reveal()
        );

        static::assertSame($metadata->reveal(), $issuer->getMetadata());
        static::assertSame($jwks->reveal(), $issuer->getJwks());
    }

    public function testUpdateJwks(): void
    {
        $metadata = $this->prophesize(IssuerMetadataInterface::class);
        $jwks = $this->prophesize(JWKSet::class);
        $jkuFactory = $this->prophesize(JKUFactory::class);

        $issuer = new Issuer(
            $metadata->reveal(),
            $jwks->reveal(),
            $jkuFactory->reveal()
        );

        static::assertSame($jwks->reveal(), $issuer->getJwks());

        $newJwks = $this->prophesize(JWKSet::class);
        $metadata->getJwksUri()->willReturn('https://jwks');
        $jkuFactory->loadFromUrl('https://jwks')
            ->willReturn($newJwks->reveal());

        $issuer->updateJwks();

        static::assertSame($newJwks->reveal(), $issuer->getJwks());
    }
}
