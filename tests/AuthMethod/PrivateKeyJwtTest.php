<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use function http_build_query;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializer;
use function json_decode;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use function time;
use TMV\OpenIdClient\AuthMethod\PrivateKeyJwt;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;

class PrivateKeyJwtTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $jwsBuilder = $this->prophesize(JWSBuilder::class);
        $serializer = $this->prophesize(JWSSerializer::class);

        $auth = new PrivateKeyJwt(
            $jwsBuilder->reveal(),
            $serializer->reveal(),
            null,
            60
        );
        static::assertSame('private_key_jwt', $auth->getSupportedMethod());
    }

    public function createRequestProvider(): array
    {
        return [
            [true],
            [false],
        ];
    }

    /**
     * @dataProvider createRequestProvider
     *
     * @param bool $jwkAsDependency
     */
    public function testCreateRequest(bool $jwkAsDependency = false): void
    {
        $jwsBuilder = $this->prophesize(JWSBuilder::class);
        $serializer = $this->prophesize(JWSSerializer::class);

        $jwk = $this->prophesize(JWK::class);
        $jwk->get('alg')->willReturn('ALG');

        $auth = new PrivateKeyJwt(
            $jwsBuilder->reveal(),
            $serializer->reveal(),
            $jwkAsDependency ? $jwk->reveal() : null,
            60
        );

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $jwks = $this->prophesize(JWKSet::class);

        if (! $jwkAsDependency) {
            $client->getJwks()->willReturn($jwks->reveal());
            $jwks->selectKey('sig')
                ->willReturn($jwk->reveal());
        }

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
            $decoded = json_decode($payload, true);

            static::assertIsArray($decoded);

            static::assertArrayHasKey('iss', $decoded);
            static::assertArrayHasKey('sub', $decoded);
            static::assertArrayHasKey('aud', $decoded);
            static::assertArrayHasKey('iat', $decoded);
            static::assertArrayHasKey('exp', $decoded);
            static::assertArrayHasKey('jti', $decoded);

            static::assertSame('bar', $decoded['foo'] ?? null);
            static::assertSame('foo', $decoded['iss'] ?? null);
            static::assertSame('foo', $decoded['sub'] ?? null);
            static::assertSame('issuer', $decoded['aud'] ?? null);
            static::assertLessThanOrEqual(time(), $decoded['iat']);
            static::assertLessThanOrEqual(time() + 60, $decoded['exp']);
            static::assertGreaterThan(time(), $decoded['exp']);

            return true;
        }))
            ->shouldBeCalled()
            ->willReturn($jwsBuilder3->reveal());

        $jwsBuilder3->addSignature($jwk, Argument::allOf(
            Argument::type('array'),
            Argument::withEntry('alg', 'ALG'),
            Argument::withKey('jti')
        ))
            ->shouldBeCalled()
            ->willReturn($jwsBuilder4);
        $jwsBuilder4->build()->willReturn($jws->reveal());

        $serializer->serialize($jws->reveal(), 0)
            ->shouldBeCalled()
            ->willReturn('assertion');

        $body = http_build_query([
            'client_id' => 'foo',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => 'assertion',
            'foo' => 'bar',
        ]);

        $stream->write($body)->shouldBeCalled();
        $request->getBody()->willReturn($stream->reveal());

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        static::assertSame($request->reveal(), $result);
    }
}
