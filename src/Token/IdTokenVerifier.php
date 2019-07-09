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
use TMV\OpenIdClient\ClaimChecker\AuthTimeChecker;
use TMV\OpenIdClient\ClaimChecker\AzpChecker;
use TMV\OpenIdClient\ClaimChecker\NonceChecker;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\jose_secret_key;
use TMV\OpenIdClient\Model\AuthSessionInterface;

class IdTokenVerifier implements IdTokenVerifierInterface
{
    /** @var AlgorithmManager */
    private $algorithmManager;

    /** @var bool */
    private $aadIssValidation;

    /** @var int */
    private $clockTolerance = 0;

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

    public function validateUserinfoToken(
        ClientInterface $client,
        string $idToken,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): array {
        return $this->validate($client, $idToken, $authSession, true, $maxAge);
    }

    public function validateIdToken(
        ClientInterface $client,
        string $idToken,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): array {
        return $this->validate($client, $idToken, $authSession, false, $maxAge);
    }

    private function validate(
        ClientInterface $client,
        string $idToken,
        ?AuthSessionInterface $authSession = null,
        bool $fromUserInfo = false,
        ?int $maxAge = null
    ): array {
        $metadata = $client->getMetadata();
        $expectedAlg = $fromUserInfo
            ? $metadata->getUserinfoSignedResponseAlg()
            : $metadata->getIdTokenSignedResponseAlg();

        if (! $expectedAlg) {
            throw new RuntimeException('Unable to verify id_token without an alg value');
        }

        $header = \json_decode(base64url_decode(\explode('.', $idToken)[0] ?? '{}'), true);

        if ($expectedAlg !== ($header['alg'] ?? '')) {
            throw new RuntimeException(\sprintf('Unexpected JWS alg received, expected %s, got: %s', $expectedAlg, $header['alg'] ?? ''));
        }

        $payload = \json_decode(base64url_decode(\explode('.', $idToken)[1] ?? '{}'), true);

        if (! \is_array($payload)) {
            throw new InvalidArgumentException('Unable to decode token payload');
        }

        $expectedIssuer = $client->getIssuer()->getMetadata()->getIssuer();

        if ($this->aadIssValidation) {
            $expectedIssuer = \str_replace('{tenantid}', $payload['tid'] ?? '', $expectedIssuer);
        }

        $nonce = $authSession ? $authSession->getNonce() : null;

        $claimCheckers = [
            new IssuerChecker([$expectedIssuer]),
            new IssuedAtChecker($this->clockTolerance),
            new AudienceChecker($metadata->getClientId()),
            new ExpirationTimeChecker($this->clockTolerance),
            new NotBeforeChecker($this->clockTolerance),
            new AzpChecker($metadata->getClientId()),
            $maxAge ? new AuthTimeChecker($maxAge, $this->clockTolerance) : null,
            $nonce ? new NonceChecker($nonce) : null,
        ];

        $requiredClaims = [];

        if (! $fromUserInfo) {
            $requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        }

        if ($maxAge || (null !== $maxAge && $metadata->get('require_auth_time'))) {
            $requiredClaims[] = 'auth_time';
        }

        $claimCheckerManager = new ClaimCheckerManager(\array_filter($claimCheckers));

        $claimCheckerManager->check($payload, \array_filter($requiredClaims));

        if ('none' === $expectedAlg) {
            return $payload;
        }

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($idToken);

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

        $kid = $header['kid'] ?? null;

        if ($kid) {
            $jwk = $jwks->selectKey('sig', null, ['kid' => $kid]);
            if (! $jwk) {
                throw new RuntimeException('Unable to find the jwk with the provided kid: ' . $kid);
            }

            $result = $jwsVerifier->verifyWithKey($jws, $jwk, 0);
        } else {
            $result = $jwsVerifier->verifyWithKeySet($jws, $jwks, 0);
        }

        if (! $result) {
            throw new InvalidArgumentException('Failed to validate JWT signature');
        }

        return $payload;
    }
}
