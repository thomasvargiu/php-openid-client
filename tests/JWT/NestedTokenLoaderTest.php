<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\JWT;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\IssuerInterface;
use TMV\OpenIdClient\JWT\NestedTokenLoader;
use Jose\Component\NestedToken\NestedTokenLoader as WTNestedTokenLoader;
use PHPUnit\Framework\TestCase;

class NestedTokenLoaderTest extends TestCase
{

    public function testHappyPath(): void
    {
        $wtLoader = $this->prophesize(WTNestedTokenLoader::class);
        $claimCheckerManager = $this->prophesize(ClaimCheckerManager::class);
        $mandatoryClaims = ['foo'];

        $loader = new NestedTokenLoader(
            $wtLoader->reveal(),
            $claimCheckerManager->reveal(),
            $mandatoryClaims
        );

        $content = 'foo';
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $clientJwks = $this->prophesize(JWKSet::class);
        $issuerJwks = $this->prophesize(JWKSet::class);
        $jws = $this->prophesize(JWS::class);

        $client->getIssuer()->willReturn($issuer->reveal());
        $client->getJWKS()->willReturn($clientJwks->reveal());
        $issuer->getJwks()->willReturn($issuerJwks->reveal());

        $wtLoader->load(
            $content,
            $clientJwks->reveal(),
            $issuerJwks->reveal()
        )
            ->shouldBeCalled()
            ->willReturn($jws->reveal());

        $jws->getPayload()->willReturn('{"foo":"bar"}');

        $claimCheckerManager->check(['foo' => 'bar'], $mandatoryClaims)
            ->shouldBeCalled();

        $result = $loader->load($content, $client->reveal());

        $this->assertSame($jws->reveal(), $result);
    }
}
