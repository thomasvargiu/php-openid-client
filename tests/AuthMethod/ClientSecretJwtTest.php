<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\AuthMethod\ClientSecretJwt;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\IssuerInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;

class ClientSecretJwtTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new ClientSecretJwt($streamFactory->reveal());
        $this->assertSame('client_secret_jwt', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);
        $jwsBuilder = $this->prophesize(JWSBuilder::class);
        $serializer = $this->prophesize(Serializer::class);

        $auth = new ClientSecretJwt(
            $streamFactory->reveal(),
            $jwsBuilder->reveal(),
            $serializer->reveal()
        );

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $requestWithBody = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);

        $client->getMetadata()->willReturn($metadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $metadata->getClientId()->willReturn('foo');
        $metadata->getClientSecret()->willReturn('bar');
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $issuerMetadata->getIssuer()->willReturn('issuer');

        $jwsBuilder2 = $this->prophesize(JWSBuilder::class);
        $jwsBuilder3 = $this->prophesize(JWSBuilder::class);
        $jwsBuilder4 = $this->prophesize(JWSBuilder::class);
        $jws = $this->prophesize(JWS::class);

        $jwsBuilder->create()->shouldBeCalled()->willReturn($jwsBuilder2->reveal());
        $jwsBuilder2->withPayload(Argument::that(function (string $payload) {
            $decoded = \json_decode($payload, true);

            $this->assertIsArray($decoded);

            $this->assertArrayHasKey('iss', $decoded);
            $this->assertArrayHasKey('sub', $decoded);
            $this->assertArrayHasKey('aud', $decoded);
            $this->assertArrayHasKey('iat', $decoded);
            $this->assertArrayHasKey('exp', $decoded);
            $this->assertArrayHasKey('jti', $decoded);

            $this->assertSame('bar', $decoded['foo'] ?? null);
            $this->assertSame('foo', $decoded['iss'] ?? null);
            $this->assertSame('foo', $decoded['sub'] ?? null);
            $this->assertSame('issuer', $decoded['aud'] ?? null);
            $this->assertLessThanOrEqual(time(), $decoded['iat']);
            $this->assertLessThanOrEqual(time() + 60, $decoded['exp']);
            $this->assertGreaterThan(time(), $decoded['exp']);

            return true;
        }))
            ->shouldBeCalled()
            ->willReturn($jwsBuilder3->reveal());

        $jwsBuilder3->addSignature(Argument::allOf(
            Argument::type(JWK::class),
            Argument::that(function (JWK $jwk) {
                $this->assertSame('oct', $jwk->get('kty'));
                $this->assertSame('bar', $jwk->get('k'));

                return true;
            })
        ), Argument::allOf(
            Argument::type('array'),
            Argument::withEntry('alg', 'HS256'),
            Argument::withKey('jti')
        ))
            ->shouldBeCalled()
            ->willReturn($jwsBuilder4);
        $jwsBuilder4->build()->willReturn($jws->reveal());

        $serializer->serialize($jws->reveal(), 0)
            ->shouldBeCalled()
            ->willReturn('assertion');

        $body = \http_build_query([
            'client_id' => 'foo',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => 'assertion',
        ]);
        $streamFactory->createStream($body)
            ->shouldBeCalled()
            ->willReturn($stream->reveal());

        $request->withBody($stream->reveal())
            ->shouldBeCalled()
            ->willReturn($requestWithBody->reveal());

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        $this->assertSame($requestWithBody->reveal(), $result);
    }
}
