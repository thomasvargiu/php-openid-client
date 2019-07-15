<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use function array_merge;
use function class_exists;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use function json_encode;
use function random_bytes;
use function time;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\LogicException;
use function TMV\OpenIdClient\jose_secret_key;

final class ClientSecretJwt extends AbstractJwtAuth
{
    /** @var null|JWSBuilder */
    private $jwsBuilder;

    /** @var JWSSerializer */
    private $jwsSerializer;

    /**
     * ClientSecretJwt constructor.
     *
     * @param null|JWSBuilder $jwsBuilder
     * @param null|JWSSerializer $jwsSerializer
     */
    public function __construct(
        ?JWSBuilder $jwsBuilder = null,
        ?JWSSerializer $jwsSerializer = null
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
        if (null !== $this->jwsBuilder) {
            return $this->jwsBuilder;
        }

        if (! class_exists(HS256::class)) {
            throw new LogicException('To use the client_secret_jwt auth method you should install web-token/jwt-signature-algorithm-hmac package');
        }

        return $this->jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
    }

    protected function createAuthJwt(OpenIDClient $client, array $claims = []): string
    {
        $clientSecret = $client->getMetadata()->getClientSecret();

        if (null === $clientSecret) {
            throw new InvalidArgumentException($this->getSupportedMethod() . ' cannot be used without client_secret metadata');
        }

        $clientId = $client->getMetadata()->getClientId();
        $issuer = $client->getIssuer();
        $issuerMetadata = $issuer->getMetadata();

        $jwk = jose_secret_key($clientSecret);

        $time = time();
        $jti = base64url_encode(random_bytes(32));

        /** @var string $payload */
        $payload = json_encode(array_merge(
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
