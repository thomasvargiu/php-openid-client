<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\jose_secret_key;

class TokenDecrypter implements TokenDecrypterInterface
{
    /** @var AlgorithmManager */
    private $algorithmManager;

    /**
     * TokenDecrypter constructor.
     *
     * @param AlgorithmManager $algorithmManager
     */
    public function __construct(?AlgorithmManager $algorithmManager = null)
    {
        $this->algorithmManager = $algorithmManager ?: new AlgorithmManager([]);
    }

    public function decryptToken(ClientInterface $client, string $token, string $use = 'id_token'): string
    {
        $metadata = $client->getMetadata();
        $expectedAlg = $metadata->get($use . '_encrypted_response_alg');
        $expectedEnc = $metadata->get($use . '_encrypted_response_enc');

        if (! $expectedAlg) {
            return $token;
        }

        $header = \json_decode(base64url_decode(\explode('.', $token)[0] ?? '{}'), true);

        if ($expectedAlg !== ($header['alg'] ?? '')) {
            throw new RuntimeException(\sprintf('Unexpected JWE alg received, expected %s, got: %s', $expectedAlg, $header['alg'] ?? ''));
        }

        if ($expectedEnc !== ($header['enc'] ?? '')) {
            throw new RuntimeException(\sprintf('Unexpected JWE enc received, expected %s, got: %s', $expectedEnc, $header['enc'] ?? ''));
        }

        if (! \class_exists(JWELoader::class)) {
            throw new LogicException('In order to decrypt JWT you should install web-token/jwt-encryption package');
        }

        $serializer = new CompactSerializer();
        $jweLoader = new JWELoader(
            new JWESerializerManager([$serializer]),
            new JWEDecrypter($this->algorithmManager, $this->algorithmManager, new CompressionMethodManager([new Deflate()])),
            null
        );

        if (\preg_match('/^(?:RSA|ECDH)/', $expectedAlg)) {
            $jwks = $client->getJWKS();
        } else {
            $jwk = jose_secret_key($metadata->getClientSecret() ?: '', $expectedAlg === 'dir' ? $expectedEnc : $expectedAlg);
            $jwks = new JWKSet([$jwk]);
        }

        return $serializer->serialize($jweLoader->loadAndDecryptWithKeySet($token, $jwks, $recipient));
    }
}
