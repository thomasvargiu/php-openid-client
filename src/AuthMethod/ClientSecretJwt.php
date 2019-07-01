<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Jose\Component\Signature\Serializer\Serializer;
use Psr\Http\Message\StreamFactoryInterface;
use Ramsey\Uuid\Uuid;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

final class ClientSecretJwt extends AbstractJwtAuth
{
    /** @var JWSBuilder */
    private $jwsBuilder;
    /** @var Serializer */
    private $jwsSerializer;

    /**
     * ClientSecretJwt constructor.
     * @param null|StreamFactoryInterface $streamFactory
     * @param null|JWSBuilder $jwsBuilder
     * @param null|Serializer $jwsSerializer
     */
    public function __construct(
        ?StreamFactoryInterface $streamFactory = null,
        ?JWSBuilder $jwsBuilder = null,
        ?Serializer $jwsSerializer = null
    ) {
        parent::__construct($streamFactory);

        $this->jwsBuilder = $jwsBuilder ?: new JWSBuilder(new AlgorithmManager([new HS256()]));
        $this->jwsSerializer = $jwsSerializer ?: new CompactSerializer();
    }

    public function getSupportedMethod(): string
    {
        return 'client_secret_jwt';
    }

    protected function createAuthJwt(OpenIDClient $client, array $claims = []): string
    {
        $issuer = $client->getIssuer();
        $issuerMetadata = $issuer->getMetadata();

        $clientId = $client->getMetadata()->getClientId();
        $clientSecret = $client->getMetadata()->getClientSecret();

        if (! $clientSecret) {
            throw new InvalidArgumentException($this->getSupportedMethod() . ' cannot be used without client_secret metadata');
        }

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => $clientSecret,
        ]);

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
                'exp' => $time + 60,
                'jti' => $jti,
            ]
        ));

        $jws = $this->jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'HS256', 'jti' => $jti])
            ->build();

        return $this->jwsSerializer->serialize($jws, 0);
    }
}
