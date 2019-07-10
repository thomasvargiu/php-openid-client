<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\RequestObject;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer as EncryptionCompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer as JWESerializer;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as SignatureCompactSerializer;
use Jose\Component\Signature\Serializer\Serializer as JWSSerializer;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\jose_secret_key;

class RequestTokenFactory
{
    /** @var JWSBuilder */
    private $jwsBuilder;

    /** @var JWEBuilder */
    private $jweBuilder;

    /** @var JWSSerializer */
    private $signatureSerializer;

    /** @var JWESerializer */
    private $encryptionSerializer;

    public function __construct(
        ?AlgorithmManager $algorithmManager = null,
        ?JWSBuilder $jwsBuilder = null,
        ?JWEBuilder $jweBuilder = null,
        ?JWSSerializer $signatureSerializer = null,
        ?JWESerializer $encryptionSerializer = null
    ) {
        $algorithmManager = $algorithmManager ?: new AlgorithmManager([new None(), new RS256()]);
        $this->jwsBuilder = $jwsBuilder ?: new JWSBuilder($algorithmManager);
        $this->jweBuilder = $jweBuilder ?: new JWEBuilder(
            $algorithmManager,
            $algorithmManager,
            new CompressionMethodManager([new Deflate()])
        );
        $this->signatureSerializer = $signatureSerializer ?: new SignatureCompactSerializer();
        $this->encryptionSerializer = $encryptionSerializer ?: new EncryptionCompactSerializer();
    }

    public function create(ClientInterface $client, array $params = []): string
    {
        $payload = $this->createPayload($client, $params);
        $signedToken = $this->createSignedToken($client, $payload);

        return $this->createEncryptedToken($client, $signedToken);
    }

    private function createPayload(ClientInterface $client, array $params = []): string
    {
        $metadata = $client->getMetadata();
        $issuer = $client->getIssuer();

        $payload = \json_encode(\array_merge($params, [
            'iss' => $metadata->getClientId(),
            'aud' => $issuer->getMetadata()->getIssuer(),
            'client_id' => $metadata->getClientId(),
            'jti' => \bin2hex(\random_bytes(32)),
            'iat' => \time(),
            'exp' => \time() + 300,
        ]));

        if (! $payload) {
            throw new RuntimeException('Unable to encode payload');
        }

        return $payload;
    }

    private function createSignedToken(ClientInterface $client, string $payload): string
    {
        $metadata = $client->getMetadata();

        /** @var string $alg */
        $alg = $metadata->get('request_object_signing_alg') ?: 'none';

        $header = ['alg' => $alg];

        if ('none' === $alg) {
            return \implode('.', [
                base64url_encode((string) \json_encode($header)),
                base64url_encode($payload),
                '',
            ]);
        }

        if (0 === \strpos($alg, 'HS')) {
            $jwk = jose_secret_key($metadata->getClientSecret() ?: '');
        } else {
            $jwk = $client->getJWKS()->selectKey('sig', null, ['alg' => $alg]);

            if (! $jwk) {
                throw new RuntimeException('No key to sign with alg ' . $alg);
            }
        }

        if ($kid = $jwk->get('kid')) {
            $header['kid'] = $kid;
        }

        $jws = $this->jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();

        return $this->signatureSerializer->serialize($jws, 0);
    }

    private function createEncryptedToken(ClientInterface $client, string $payload): string
    {
        $metadata = $client->getMetadata();
        $issuer = $client->getIssuer();

        /** @var null|string $alg */
        $alg = $metadata->get('request_object_encryption_alg');

        if (! $alg) {
            return $payload;
        }

        /** @var null|string $enc */
        $enc = $metadata->get('request_object_encryption_enc');

        if (\preg_match('/^(RSA|ECDH)/', $alg)) {
            $jwk = $issuer->getJwks()->selectKey('enc', null, ['alg' => $alg, 'enc' => $enc]);

            if (! $jwk) {
                throw new RuntimeException('No key to sign with alg ' . $alg);
            }
        } else {
            $jwk = jose_secret_key(
                $metadata->getClientSecret() ?: '',
                'dir' === $alg ? $enc : $alg
            );
        }

        $jwe = $this->jweBuilder->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($jwk)
            ->build();

        return $this->encryptionSerializer->serialize($jwe, 0);
    }
}
