<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\Serializer;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;

final class PrivateKeyJwt extends AbstractJwtAuth
{
    /** @var JWSBuilder */
    private $jwsBuilder;

    /** @var Serializer */
    private $jwsSerializer;

    /** @var null|JWK */
    private $jwk;

    /** @var int */
    private $tokenTTL;

    /**
     * PrivateKeyJwt constructor.
     *
     * @param null|JWSBuilder $jwsBuilder
     * @param null|Serializer $serializer
     * @param null|JWK $jwk
     * @param int $tokenTTL
     */
    public function __construct(
        ?JWSBuilder $jwsBuilder = null,
        ?Serializer $serializer = null,
        ?JWK $jwk = null,
        int $tokenTTL = 60
    ) {
        $this->jwsBuilder = $jwsBuilder ?: new JWSBuilder(new AlgorithmManager([new RS256()]));
        $this->jwsSerializer = $serializer ?: new CompactSerializer();
        $this->jwk = $jwk;
        $this->tokenTTL = $tokenTTL;
    }

    public function getSupportedMethod(): string
    {
        return 'private_key_jwt';
    }

    protected function createAuthJwt(OpenIDClient $client, array $claims = []): string
    {
        $issuer = $client->getIssuer();
        $issuerMetadata = $issuer->getMetadata();

        $clientId = $client->getMetadata()->getClientId();

        $jwk = $this->jwk ?: $client->getJWKS()->selectKey('sig');

        if (! $jwk) {
            throw new RuntimeException('Unable to get a client signature jwk');
        }

        $time = \time();
        $jti = base64url_encode(\random_bytes(32));

        /** @var string $payload */
        $payload = \json_encode(\array_merge(
            $claims,
            [
                'iss' => $clientId,
                'sub' => $clientId,
                'aud' => $issuerMetadata->getIssuer(),
                'iat' => $time,
                'exp' => $time + $this->tokenTTL,
                'jti' => $jti,
            ]
        ));

        $jws = $this->jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => $jwk->get('alg'), 'jti' => $jti])
            ->build();

        return $this->jwsSerializer->serialize($jws, 0);
    }
}
