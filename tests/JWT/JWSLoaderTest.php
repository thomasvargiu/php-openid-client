<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\JWT;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Prophecy\Argument;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\IssuerInterface;
use TMV\OpenIdClient\JWT\JWSLoader;
use Jose\Component\Signature\JWSLoader as WTJWSLoader;
use PHPUnit\Framework\TestCase;

class JWSLoaderTest extends TestCase
{

    public function testHappyPath(): void
    {
        $wtJwsLoader = $this->prophesize(WTJWSLoader::class);
        $claimCheckerManager = $this->prophesize(ClaimCheckerManager::class);
        $mandatoryClaims = ['foo'];

        $loader = new JWSLoader(
            $wtJwsLoader->reveal(),
            $claimCheckerManager->reveal(),
            $mandatoryClaims
        );

        $content = 'foo';
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerJwks = $this->prophesize(JWKSet::class);
        $jws = $this->prophesize(JWS::class);

        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getJwks()->willReturn($issuerJwks->reveal());

        $wtJwsLoader->loadAndVerifyWithKeySet(
            $content,
            $issuerJwks->reveal(),
            Argument::any()
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
