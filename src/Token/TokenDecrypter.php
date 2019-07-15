<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use function class_exists;
use function explode;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use function json_decode;
use function preg_match;
use function sprintf;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\jose_secret_key;

class TokenDecrypter implements TokenDecrypterInterface
{
    /** @var JWELoader */
    private $jweLoader;

    public function __construct(?JWELoader $JWELoader = null)
    {
        $this->jweLoader = $JWELoader ?: new JWELoader(
            new JWESerializerManager([new CompactSerializer()]),
            new JWEDecrypter(new AlgorithmManager([]), new AlgorithmManager([]), new CompressionMethodManager([new Deflate()])),
            null
        );
    }

    public function decryptToken(ClientInterface $client, string $token, string $use = 'id_token'): string
    {
        $metadata = $client->getMetadata();
        $expectedAlg = $metadata->get($use . '_encrypted_response_alg');
        $expectedEnc = $metadata->get($use . '_encrypted_response_enc');

        if (null === $expectedAlg) {
            return $token;
        }

        $header = json_decode(base64url_decode(explode('.', $token)[0] ?? '{}'), true);

        if ($expectedAlg !== ($header['alg'] ?? '')) {
            throw new RuntimeException(sprintf('Unexpected JWE alg received, expected %s, got: %s', $expectedAlg, $header['alg'] ?? ''));
        }

        if ($expectedEnc !== ($header['enc'] ?? '')) {
            throw new RuntimeException(sprintf('Unexpected JWE enc received, expected %s, got: %s', $expectedEnc, $header['enc'] ?? ''));
        }

        if (! class_exists(JWELoader::class)) {
            throw new LogicException('In order to decrypt JWT you should install web-token/jwt-encryption package');
        }

        if ((bool) preg_match('/^(?:RSA|ECDH)/', $expectedAlg)) {
            $jwks = $client->getJwks();
        } else {
            $jwk = jose_secret_key($metadata->getClientSecret() ?: '', $expectedAlg === 'dir' ? $expectedEnc : $expectedAlg);
            $jwks = new JWKSet([$jwk]);
        }

        return $this->jweLoader->loadAndDecryptWithKeySet($token, $jwks, $recipient)->getPayload() ?: '';
    }
}
