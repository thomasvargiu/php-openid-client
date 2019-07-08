<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\Serializer;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\LogicException;
use function TMV\OpenIdClient\jose_secret_key;

final class ClientSecretJwt extends AbstractJwtAuth
{
    /** @var null|JWSBuilder */
    private $jwsBuilder;

    /** @var Serializer */
    private $jwsSerializer;

    /**
     * ClientSecretJwt constructor.
     *
     * @param null|JWSBuilder $jwsBuilder
     * @param null|Serializer $jwsSerializer
     */
    public function __construct(
        ?JWSBuilder $jwsBuilder = null,
        ?Serializer $jwsSerializer = null
    ) {
        $this->jwsBuilder = $jwsBuilder;
        $this->jwsSerializer = $jwsSerializer ?: new CompactSerializer();
    }

    public function getSupportedMethod(): string
    {
        return 'client_secret_jwt';
    }

    private function getJwsBuilder(): JWSBuilder
    {
        if ($this->jwsBuilder) {
            return $this->jwsBuilder;
        }

        if (! \class_exists(HS256::class)) {
            throw new LogicException('To use the client_secret_jwt auth method you should install web-token/jwt-signature-algorithm-hmac package');
        }

        return $this->jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
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

        $jwk = jose_secret_key($clientSecret);

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
                'exp' => $time + 60,
                'jti' => $jti,
            ]
        ));

        $jws = $this->getJwsBuilder()->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'HS256', 'jti' => $jti])
            ->build();

        return $this->jwsSerializer->serialize($jws, 0);
    }
}
