<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\RequestObject;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializer;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use function TMV\OpenIdClient\base64url_decode;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;
use TMV\OpenIdClient\RequestObject\RequestObjectFactory;

class RequestObjectFactoryTest extends TestCase
{
    /** @var ObjectProphecy|AlgorithmManager */
    private $algorithmManager;

    /** @var ObjectProphecy|JWSBuilder */
    private $jwsBuilder;

    /** @var ObjectProphecy|JWEBuilder */
    private $jweBuilder;

    /** @var ObjectProphecy|JWSSerializer */
    private $jwsSerializer;

    /** @var ObjectProphecy|JWESerializer */
    private $jweSerializer;

    /** @var ObjectProphecy|ClientInterface */
    private $client;

    /** @var ObjectProphecy|ClientMetadataInterface */
    private $clientMetadata;

    /** @var ObjectProphecy|IssuerInterface */
    private $issuer;

    /** @var ObjectProphecy|IssuerMetadataInterface */
    private $issuerMetadata;

    /** @var RequestObjectFactory */
    private $factory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->algorithmManager = $this->prophesize(AlgorithmManager::class);
        $this->jwsBuilder = $this->prophesize(JWSBuilder::class);
        $this->jweBuilder = $this->prophesize(JWEBuilder::class);
        $this->jwsSerializer = $this->prophesize(JWSSerializer::class);
        $this->jweSerializer = $this->prophesize(JWESerializer::class);

        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);

        $client->getIssuer()->willReturn($issuer->reveal());
        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getClientSecret()->willReturn('client-secret');
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $issuerMetadata->getIssuer()->willReturn('http://issuer.com');

        $this->client = $client;
        $this->clientMetadata = $clientMetadata;
        $this->issuer = $issuer;
        $this->issuerMetadata = $issuerMetadata;

        $this->factory = new RequestObjectFactory(
            $this->algorithmManager->reveal(),
            $this->jwsBuilder->reveal(),
            $this->jweBuilder->reveal(),
            $this->jwsSerializer->reveal(),
            $this->jweSerializer->reveal()
        );
    }

    public function testMinimalConstructor(): void
    {
        $factory = new RequestObjectFactory();
        self::assertInstanceOf(RequestObjectFactory::class, $factory);
    }

    public function testCreateWithNoSignAndNoEnc(): void
    {
        $this->clientMetadata->get('request_object_signing_alg')->willReturn('none');
        $this->clientMetadata->get('request_object_encryption_alg')->willReturn(null);
        $this->clientMetadata->get('request_object_encryption_enc')->willReturn(null);

        $token = $this->factory->create($this->client->reveal(), ['foo' => 'bar']);

        [$header, $payload] = \explode('.', $token);
        $header = \json_decode(base64url_decode($header), true);
        $payload = \json_decode(base64url_decode($payload), true);

        self::assertSame('none', $header['alg'] ?? null);
        self::assertSame('client-id', $payload['iss'] ?? null);
        self::assertSame('client-id', $payload['client_id'] ?? null);
        self::assertSame('http://issuer.com', $payload['aud'] ?? null);
        self::assertSame('bar', $payload['foo'] ?? null);
        self::assertIsString($payload['jti'] ?? null);
        self::assertIsInt($payload['iat'] ?? null);
        self::assertIsInt($payload['exp'] ?? null);
    }

    public function testCreateWithSymSignAndNoEnc(): void
    {
        $this->clientMetadata->get('request_object_signing_alg')->willReturn('HS256');
        $this->clientMetadata->get('request_object_encryption_alg')->willReturn(null);
        $this->clientMetadata->get('request_object_encryption_enc')->willReturn(null);

        $jws = $this->prophesize(JWS::class);

        $this->jwsBuilder->create()->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->withPayload(Argument::type('string'))->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->addSignature(Argument::allOf(
            Argument::type(JWK::class),
            Argument::that(function (JWK $jwk) {
                return $jwk->get('k') === base64url_encode('client-secret');
            }),
            Argument::that(function (JWK $jwk) {
                return $jwk->get('kty') === 'oct';
            })
        ), [
            'alg' => 'HS256',
            'typ' => 'JWT',
        ])
            ->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->build()->willReturn($jws->reveal());

        $this->jwsSerializer->serialize($jws->reveal(), 0)
            ->willReturn('token');

        $token = $this->factory->create($this->client->reveal(), ['foo' => 'bar']);

        self::assertSame('token', $token);
    }

    public function testCreateWithAsymSignAndNoEnc(): void
    {
        $this->clientMetadata->get('request_object_signing_alg')->willReturn('RS256');
        $this->clientMetadata->get('request_object_encryption_alg')->willReturn(null);
        $this->clientMetadata->get('request_object_encryption_enc')->willReturn(null);

        $alg = $this->prophesize(Algorithm::class);
        $this->algorithmManager->get('RS256')->willReturn($alg->reveal());

        $jwk = $this->prophesize(JWK::class);
        $jwk->has('kty')->willReturn(true);
        $jwk->get('kty')->willReturn('something');
        $jwk->has('kid')->willReturn(true);
        $jwk->get('kid')->willReturn('some-key-id');
        $jwks = $this->prophesize(JWKSet::class);
        $jwks->selectKey('sig', $alg->reveal())->willReturn($jwk->reveal());
        $this->client->getJwks()->willReturn($jwks->reveal());

        $jws = $this->prophesize(JWS::class);

        $this->jwsBuilder->create()->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->withPayload(Argument::type('string'))->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->addSignature($jwk->reveal(), [
            'alg' => 'RS256',
            'typ' => 'JWT',
            'kid' => 'some-key-id',
        ])
            ->willReturn($this->jwsBuilder->reveal());
        $this->jwsBuilder->build()->willReturn($jws->reveal());

        $this->jwsSerializer->serialize($jws->reveal(), 0)
            ->willReturn('token');

        $token = $this->factory->create($this->client->reveal(), ['foo' => 'bar']);

        self::assertSame('token', $token);
    }

    public function testCreateWithNoSignAndSymEnc(): void
    {
        $this->clientMetadata->get('request_object_signing_alg')->willReturn('none');
        $this->clientMetadata->get('request_object_encryption_alg')->willReturn('ASY1');
        $this->clientMetadata->get('request_object_encryption_enc')->willReturn('ASY2');

        $jwe = $this->prophesize(JWE::class);

        $this->jweBuilder->create()->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->withPayload(Argument::type('string'))->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->withSharedProtectedHeader([
            'alg' => 'ASY1',
            'enc' => 'ASY2',
            'cty' => 'JWT',
        ])->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->addRecipient(Argument::allOf(
            Argument::type(JWK::class),
            Argument::that(function (JWK $jwk) {
                return $jwk->get('k') === base64url_encode('client-secret');
            }),
            Argument::that(function (JWK $jwk) {
                return $jwk->get('kty') === 'oct';
            })
        ))
            ->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->build()->willReturn($jwe->reveal());

        $this->jweSerializer->serialize($jwe->reveal(), 0)
            ->willReturn('token');

        $token = $this->factory->create($this->client->reveal(), ['foo' => 'bar']);

        self::assertSame('token', $token);
    }

    public function testCreateWithNoSignAndAsymEnc(): void
    {
        $this->clientMetadata->get('request_object_signing_alg')->willReturn('none');
        $this->clientMetadata->get('request_object_encryption_alg')->willReturn('RSA-OEAP');
        $this->clientMetadata->get('request_object_encryption_enc')->willReturn('ASY2');

        $alg = $this->prophesize(Algorithm::class);
        $this->algorithmManager->get('RSA-OEAP')->willReturn($alg->reveal());

        $jwk = $this->prophesize(JWK::class);
        $jwk->has('kty')->willReturn(true);
        $jwk->get('kty')->willReturn('something');
        $jwk->has('kid')->willReturn(true);
        $jwk->get('kid')->willReturn('some-key-id');
        $jwks = $this->prophesize(JWKSet::class);
        $jwks->selectKey('enc', $alg->reveal())->willReturn($jwk->reveal());
        $this->issuer->getJwks()->willReturn($jwks->reveal());

        $jwe = $this->prophesize(JWE::class);

        $this->jweBuilder->create()->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->withPayload(Argument::type('string'))->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->withSharedProtectedHeader([
            'alg' => 'RSA-OEAP',
            'enc' => 'ASY2',
            'cty' => 'JWT',
            'kid' => 'some-key-id',
        ])->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->addRecipient($jwk->reveal())
            ->willReturn($this->jweBuilder->reveal());
        $this->jweBuilder->build()->willReturn($jwe->reveal());

        $this->jweSerializer->serialize($jwe->reveal(), 0)
            ->willReturn('token');

        $token = $this->factory->create($this->client->reveal(), ['foo' => 'bar']);

        self::assertSame('token', $token);
    }
}
