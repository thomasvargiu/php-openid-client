<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use Psr\Http\Message\StreamFactoryInterface;
use Ramsey\Uuid\Uuid;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;

final class PrivateKeyJwtAuth extends AbstractJwtAuth
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
     * @param JWSBuilder $jwsBuilder
     * @param Serializer $serializer
     * @param string|null $kid
     * @param int $tokenTTL
     * @param null|StreamFactoryInterface $streamFactory
     */
    public function __construct(
        JWSBuilder $jwsBuilder,
        Serializer $serializer,
        ?string $kid = null,
        int $tokenTTL = 60,
        ?StreamFactoryInterface $streamFactory = null
    )
    {
        parent::__construct($streamFactory);

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

        $time = time();
        $jti = Uuid::uuid4()->toString();

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
