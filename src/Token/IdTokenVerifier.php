<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use function array_filter;
use function explode;
use function is_array;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use function sprintf;
use function str_replace;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\ClaimChecker\AuthTimeChecker;
use TMV\OpenIdClient\ClaimChecker\AzpChecker;
use TMV\OpenIdClient\ClaimChecker\NonceChecker;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Session\AuthSessionInterface;

class IdTokenVerifier extends AbstractTokenVerifier implements IdTokenVerifierInterface
{
    /** @var JWSVerifier */
    private $jwsVerifier;

    /** @var bool */
    private $aadIssValidation;

    /** @var int */
    private $clockTolerance;

    public function __construct(
        ?JWSVerifier $jwsVerifier = null,
        bool $aadIssValidation = false,
        int $clockTolerance = 0
    ) {
        $this->jwsVerifier = $jwsVerifier ?: new JWSVerifier(new AlgorithmManager([new RS256()]));
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

        if (null === $expectedAlg) {
            throw new RuntimeException('Unable to verify id_token without an alg value');
        }

        $header = json_decode(base64url_decode(explode('.', $idToken)[0] ?? '{}'), true);

        if ($expectedAlg !== ($header['alg'] ?? '')) {
            throw new RuntimeException(sprintf('Unexpected JWS alg received, expected %s, got: %s', $expectedAlg, $header['alg'] ?? ''));
        }

        $payload = json_decode(base64url_decode(explode('.', $idToken)[1] ?? '{}'), true);

        if (! is_array($payload)) {
            throw new InvalidArgumentException('Unable to decode token payload');
        }

        $expectedIssuer = $client->getIssuer()->getMetadata()->getIssuer();

        if ($this->aadIssValidation) {
            $expectedIssuer = str_replace('{tenantid}', $payload['tid'] ?? '', $expectedIssuer);
        }

        $nonce = null !== $authSession ? $authSession->getNonce() : null;

        $claimCheckers = [
            new IssuerChecker([$expectedIssuer]),
            new IssuedAtChecker($this->clockTolerance),
            new AudienceChecker($metadata->getClientId()),
            new ExpirationTimeChecker($this->clockTolerance),
            new NotBeforeChecker($this->clockTolerance),
            new AzpChecker($metadata->getClientId()),
            null !== $maxAge ? new AuthTimeChecker($maxAge, $this->clockTolerance) : null,
            null !== $nonce ? new NonceChecker($nonce) : null,
        ];

        $requiredClaims = [];

        if (! $fromUserInfo) {
            $requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        }

        if ((int) $maxAge > 0 || (null !== $maxAge && null !== $metadata->get('require_auth_time'))) {
            $requiredClaims[] = 'auth_time';
        }

        $claimCheckerManager = new ClaimCheckerManager(array_filter($claimCheckers));

        $claimCheckerManager->check($payload, array_filter($requiredClaims));

        if ('none' === $expectedAlg) {
            return $payload;
        }

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($idToken);

        /** @var string|null $kid */
        $kid = $header['kid'] ?? null;

        $jwks = $this->getSigningJWKSet($client, $expectedAlg, $kid);

        if (! $this->jwsVerifier->verifyWithKeySet($jws, $jwks, 0)) {
            throw new InvalidArgumentException('Failed to validate JWT signature');
        }

        return $payload;
    }
}
