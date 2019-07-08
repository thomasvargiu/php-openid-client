<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\ClaimChecker\AzpChecker;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\jose_secret_key;

class ResponseTokenVerifier implements ResponseTokenVerifierInterface
{
    /** @var AlgorithmManager */
    private $algorithmManager;

    /** @var bool */
    private $aadIssValidation;

    /** @var int */
    private $clockTolerance;

    /**
     * IdTokenVerifier constructor.
     *
     * @param null|AlgorithmManager $algorithmManager
     * @param bool $aadIssValidation
     * @param int $clockTolerance
     */
    public function __construct(
        ?AlgorithmManager $algorithmManager = null,
        bool $aadIssValidation = false,
        int $clockTolerance = 0
    ) {
        $this->algorithmManager = $algorithmManager ?: new AlgorithmManager([new RS256()]);
        $this->aadIssValidation = $aadIssValidation;
        $this->clockTolerance = $clockTolerance;
    }

    public function validate(ClientInterface $client, string $token): array
    {
        $metadata = $client->getMetadata();
        $expectedAlg = $metadata->getAuthorizationSignedResponseAlg();

        if (! $expectedAlg) {
            throw new RuntimeException('No authorization_signed_response_alg defined');
        }

        $header = \json_decode(base64url_decode(\explode('.', $token)[0] ?? '{}'), true);

        if ($expectedAlg !== ($header['alg'] ?? '')) {
            throw new RuntimeException(\sprintf('Unexpected JWE alg received, expected %s, got: %s', $expectedAlg, $header['alg'] ?? ''));
        }

        $payload = \json_decode(base64url_decode(\explode('.', $token)[1] ?? '{}'), true);

        if (! \is_array($payload)) {
            throw new InvalidArgumentException('Unable to decode token payload');
        }

        $expectedIssuer = $client->getIssuer()->getMetadata()->getIssuer();

        if ($this->aadIssValidation) {
            $expectedIssuer = \str_replace('{tenantid}', $payload['tid'] ?? '', $expectedIssuer);
        }

        $claimCheckers = [
            new IssuerChecker([$expectedIssuer]),
            new IssuedAtChecker($this->clockTolerance),
            new AudienceChecker($metadata->getClientId()),
            new ExpirationTimeChecker($this->clockTolerance),
            new NotBeforeChecker($this->clockTolerance),
            new AzpChecker($metadata->getClientId()),
        ];

        $requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];

        $claimCheckerManager = new ClaimCheckerManager(\array_filter($claimCheckers));

        $claimCheckerManager->check($payload, \array_filter($requiredClaims));

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($token);

        $jwsVerifier = new JWSVerifier(
            $this->algorithmManager
        );

        if (0 === \strpos($expectedAlg, 'HS')) {
            $clientSecret = $metadata->getClientSecret();

            if (! $clientSecret) {
                throw new RuntimeException('Unable to verify token without client_secret');
            }

            $jwks = new JWKSet([jose_secret_key($clientSecret)]);
        } else {
            $jwks = $client->getIssuer()->getJwks();
        }

        if (! $jwsVerifier->verifyWithKeySet($jws, $jwks, 0)) {
            throw new InvalidArgumentException('Failed to validate JWT signature');
        }

        return $payload;
    }
}
