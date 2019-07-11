<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Token;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;
use function TMV\OpenIdClient\jose_secret_key;
use TMV\OpenIdClient\Session\AuthSessionInterface;
use TMV\OpenIdClient\Token\IdTokenVerifier;

class IdTokenVerifierTest extends TestCase
{
    /** @var ObjectProphecy|JWSVerifier */
    private $jwsVerifier;

    /** @var IdTokenVerifier */
    private $verifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwsVerifier = $this->prophesize(JWSVerifier::class);
        $this->verifier = new IdTokenVerifier($this->jwsVerifier->reveal());
    }

    private function createSignedToken(array $payload, array $header, JWK $jkw): string
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new HS256(),
        ]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jwsSerializer = new CompactSerializer();

        $jws = $jwsBuilder->create()
            ->withPayload((string) \json_encode($payload))
            ->addSignature($jkw, $header)
            ->build();

        return $jwsSerializer->serialize($jws);
    }

    public function testValidateIdTokenWithNoneSignature(): void
    {
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];

        $token = \implode('.', [
            base64url_encode((string) \json_encode(['alg' => 'none'])),
            base64url_encode((string) \json_encode($payload)),
            '',
        ]);

        $client = $this->prophesize(ClientInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authSession = $this->prophesize(AuthSessionInterface::class);

        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getIdTokenSignedResponseAlg()->willReturn('none');
        $clientMetadata->get('require_auth_time')->willReturn(true);
        $issuerMetadata->getIssuer()->willReturn('https://issuer.com');

        $authSession->getNonce()->willReturn('nonce');

        $result = $this->verifier->validateIdToken($client->reveal(), $token, $authSession->reveal(), 300);

        self::assertSame($payload, $result);
    }

    public function testValidateIdToken(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwkSet = $this->prophesize(JWKSet::class);

        $client = $this->prophesize(ClientInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuer->getJwks()->willReturn($jwkSet->reveal());
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authSession = $this->prophesize(AuthSessionInterface::class);

        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getIdTokenSignedResponseAlg()->willReturn('RS256');
        $clientMetadata->get('require_auth_time')->willReturn(true);
        $issuerMetadata->getIssuer()->willReturn('https://issuer.com');

        $authSession->getNonce()->willReturn('nonce');

        $this->jwsVerifier->verifyWithKeySet(Argument::type(JWS::class), $jwkSet->reveal(), 0)
            ->willReturn(true);

        $result = $this->verifier->validateIdToken($client->reveal(), $token, $authSession->reveal(), 300);

        self::assertSame($payload, $result);
    }

    public function testValidateIdTokenWithIssuerKidNotFound(): void
    {
        $jwk2 = JWKFactory::createRSAKey(2048, [
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'kid2',
        ]);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
            'kid' => 'kid2',
        ], $jwk2);

        $jwkSet = $this->prophesize(JWKSet::class);
        $jwkSet2 = $this->prophesize(JWKSet::class);
        $jwkSet2->selectKey('sig', null, ['kid' => 'kid2'])
            ->willReturn($jwk2);

        $client = $this->prophesize(ClientInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuer->getJwks()->willReturn($jwkSet->reveal());
        $issuer->updateJwks()->shouldBeCalled()->will(function () use ($issuer, $jwkSet2): void {
            $issuer->getJwks()->willReturn($jwkSet2->reveal());
        });
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authSession = $this->prophesize(AuthSessionInterface::class);

        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getIdTokenSignedResponseAlg()->willReturn('RS256');
        $clientMetadata->get('require_auth_time')->willReturn(true);
        $issuerMetadata->getIssuer()->willReturn('https://issuer.com');

        $authSession->getNonce()->willReturn('nonce');

        $this->jwsVerifier->verifyWithKeySet(Argument::type(JWS::class), Argument::allOf(
            Argument::type(JWKSet::class),
            Argument::that(function (JWKSet $jwks) use ($jwk2) {
                return $jwks->selectKey('sig') === $jwk2;
            })
        ), 0)
            ->willReturn(true);

        $result = $this->verifier->validateIdToken($client->reveal(), $token, $authSession->reveal(), 300);

        self::assertSame($payload, $result);
    }

    public function verifyIdTokenProvider(): array
    {
        return [
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // wrong issuer
            [
                [
                    'iss' => 'https://issuer.com-wrong',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'wrong-client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong auth_time
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 400,
                ],
                false,
            ],
            // missing sub
            [
                [
                    'iss' => 'https://issuer.com',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing iss
            [
                [
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing iat
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'auth_time' => time() - 100,
                ],
                false,
            ],
        ];
    }

    /**
     * @dataProvider verifyIdTokenProvider
     *
     * @param array $payload
     * @param bool $expected
     *
     * @throws \Exception
     */
    public function testValidateIdTokenWithAsyKey(array $payload, bool $expected): void
    {
        if (! $expected) {
            $this->expectException(\Throwable::class);
        }

        $clientSecret = base64url_encode(\random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $client = $this->prophesize(ClientInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authSession = $this->prophesize(AuthSessionInterface::class);

        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getClientSecret()->willReturn($clientSecret);
        $clientMetadata->getIdTokenSignedResponseAlg()->willReturn('HS256');
        $clientMetadata->get('require_auth_time')->willReturn(true);
        $issuerMetadata->getIssuer()->willReturn('https://issuer.com');

        $authSession->getNonce()->willReturn('nonce');

        $this->jwsVerifier->verifyWithKeySet(
            Argument::type(JWS::class),
            Argument::type(JWKSet::class),
            0
        )
            ->willReturn(true);

        $result = $this->verifier->validateIdToken($client->reveal(), $token, $authSession->reveal(), 300);

        self::assertSame($payload, $result);
    }

    public function verifyUserinfoTokenProvider(): array
    {
        return [
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // wrong issuer
            [
                [
                    'iss' => 'https://issuer.com-wrong',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'wrong-client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong auth_time
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 400,
                ],
                false,
            ],
            // missing sub
            [
                [
                    'iss' => 'https://issuer.com',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // missing iss
            [
                [
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // missing aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // missing exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // missing iat
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'auth_time' => time() - 100,
                ],
                true,
            ],
        ];
    }

    /**
     * @dataProvider verifyUserinfoTokenProvider
     *
     * @param array $payload
     * @param bool $expected
     *
     * @throws \Exception
     */
    public function testValidateUserinfoTokenWithAsyKey(array $payload, bool $expected): void
    {
        if (! $expected) {
            $this->expectException(\Throwable::class);
        }

        $clientSecret = base64url_encode(\random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $client = $this->prophesize(ClientInterface::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authSession = $this->prophesize(AuthSessionInterface::class);

        $client->getMetadata()->willReturn($clientMetadata->reveal());
        $client->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $clientMetadata->getClientId()->willReturn('client-id');
        $clientMetadata->getClientSecret()->willReturn($clientSecret);
        $clientMetadata->getUserinfoSignedResponseAlg()->willReturn('HS256');
        $clientMetadata->get('require_auth_time')->willReturn(true);
        $issuerMetadata->getIssuer()->willReturn('https://issuer.com');

        $authSession->getNonce()->willReturn('nonce');

        $this->jwsVerifier->verifyWithKeySet(
            Argument::type(JWS::class),
            Argument::type(JWKSet::class),
            0
        )
            ->willReturn(true);

        $result = $this->verifier->validateUserinfoToken($client->reveal(), $token, $authSession->reveal(), 300);

        self::assertSame($payload, $result);
    }
}
