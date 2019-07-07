<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;

final class PrivateKeyJwt extends AbstractJwtAuth
{
    /** @var JWSBuilder */
    private $jwsBuilder;

    /** @var Serializer */
    private $jwsSerializer;

    /** @var null|string */
    private $kid;

    /** @var int */
    private $tokenTTL;

    /**
     * PrivateKeyJwt constructor.
     *
     * @param JWSBuilder $jwsBuilder
     * @param Serializer $serializer
     * @param string|null $kid
     * @param int $tokenTTL
     */
    public function __construct(
        JWSBuilder $jwsBuilder,
        Serializer $serializer,
        ?string $kid = null,
        int $tokenTTL = 60
    ) {
        $this->jwsBuilder = $jwsBuilder;
        $this->jwsSerializer = $serializer;
        $this->kid = $kid;
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

        $jwk = $client->getJWKS()->selectKey('sig', null, $this->kid ? ['kid' => $this->kid] : []);

        if (! $jwk) {
            throw new RuntimeException('Unable to get a client signature jwk');
        }

        $time = \time();
        $jti = \bin2hex(\random_bytes(32));

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
