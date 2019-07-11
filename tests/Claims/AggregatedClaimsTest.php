<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Claims;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use TMV\OpenIdClient\Claims\AggregateParser;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Issuer\IssuerFactoryInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;

class AggregatedClaimsTest extends TestCase
{
    public function testUnpackAggregatedClaimsWithNoClaimSources(): void
    {
        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $service = new AggregateParser(
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'eye_color' => 'src1',
                'shoe_size' => 'src1',
            ],
        ];

        $unpacked = $service->unpack($client->reveal(), $claims);

        static::assertSame($claims, $unpacked);
    }

    public function testUnpackAggregatedClaimsWithNoClaimNames(): void
    {
        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $service = new AggregateParser(
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_sources' => [
                'src1' => [
                    'JWT' => 'foo',
                ],
            ],
        ];

        $unpacked = $service->unpack($client->reveal(), $claims);

        static::assertSame($claims, $unpacked);
    }

    public function testUnpackAggregatedClaims(): void
    {
        $jwt = 'eyJhbGciOiJub25lIn0.eyJleWVfY29sb3IiOiAiYmx1ZSIsICJzaG9lX3NpemUiOiA4fQ.';

        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);

        $client->getIssuer()->willReturn($issuer->reveal());

        $service = new AggregateParser(
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'eye_color' => 'src1',
                'shoe_size' => 'src1',
            ],
            '_claim_sources' => [
                'src1' => [
                    'JWT' => $jwt,
                ],
            ],
        ];

        $unpacked = $service->unpack($client->reveal(), $claims);

        static::assertSame('blue', $unpacked['eye_color'] ?? null);
        static::assertSame(8, $unpacked['shoe_size'] ?? null);
        static::assertArrayNotHasKey('_claim_names', $unpacked);
        static::assertArrayNotHasKey('_claim_sources', $unpacked);
    }

    public function testUnpackAggregatedClaimsWithSignedJWT(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new RS256()]));
        $serializer = new CompactSerializer();
        $jws = $jwsBuilder->create()
            ->withPayload((string) json_encode([
                'eye_color' => 'blue',
            ]))
            ->addSignature($jwk, ['alg' => 'RS256', 'use' => 'sig'])
            ->build();

        $jwt = $serializer->serialize($jws, 0);

        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $jwks = $this->prophesize(JWKSet::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);

        $algorithm = $this->prophesize(Algorithm::class);
        $algorithmManager->get('RS256')->willReturn($algorithm->reveal());

        $jwks->selectKey('sig', $algorithm->reveal(), [])
            ->willReturn($jwk);

        $JWSVerifier->verifyWithKey(Argument::type(JWS::class), $jwk, 0)
            ->willReturn(true);

        $client->getIssuer()->willReturn($issuer->reveal());
        $issuerMetadata->getIssuer()->willReturn('foo-issuer');
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $issuer->getJwks()->willReturn($jwks->reveal());

        $service = new AggregateParser(
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'eye_color' => 'src1',
            ],
            '_claim_sources' => [
                'src1' => [
                    'JWT' => $jwt,
                ],
            ],
        ];

        $unpacked = $service->unpack($client->reveal(), $claims);

        static::assertSame('blue', $unpacked['eye_color'] ?? null);
        static::assertArrayNotHasKey('_claim_names', $unpacked);
        static::assertArrayNotHasKey('_claim_sources', $unpacked);
    }
}
