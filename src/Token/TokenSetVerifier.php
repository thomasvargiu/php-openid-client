<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use function array_filter;
use function array_key_exists;
use function array_merge;
use function explode;
use function is_array;
use Jose\Component\Checker\ClaimCheckerManager;
use function json_decode;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\ClaimChecker\AtHashChecker;
use TMV\OpenIdClient\ClaimChecker\CHashChecker;
use TMV\OpenIdClient\ClaimChecker\SHashChecker;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Session\AuthSessionInterface;

class TokenSetVerifier implements TokenSetVerifierInterface
{
    /** @var IdTokenVerifierInterface */
    private $idTokenVerifier;

    /**
     * TokenSetVerifier constructor.
     *
     * @param null|IdTokenVerifierInterface $idTokenVerifier
     */
    public function __construct(?IdTokenVerifierInterface $idTokenVerifier = null)
    {
        $this->idTokenVerifier = $idTokenVerifier ?: new IdTokenVerifier();
    }

    /**
     * @return IdTokenVerifierInterface
     */
    public function getIdTokenVerifier(): IdTokenVerifierInterface
    {
        return $this->idTokenVerifier;
    }

    public function validate(
        TokenSetInterface $tokenSet,
        ClientInterface $client,
        ?AuthSessionInterface $authSession = null,
        bool $fromAuthorization = true,
        ?int $maxAge = null
    ): void {
        $idToken = $tokenSet->getIdToken();

        if (null === $idToken) {
            throw new InvalidArgumentException('No id_token in token set');
        }

        $this->getIdTokenVerifier()->validateIdToken($client, $idToken, $authSession);

        $metadata = $client->getMetadata();

        $header = json_decode(base64url_decode(explode('.', $idToken)[0] ?? '{}'), true);
        $payload = json_decode(base64url_decode(explode('.', $idToken)[1] ?? '{}'), true);

        if (! is_array($payload)) {
            throw new InvalidArgumentException('Unable to decode token payload');
        }

        $claimCheckers = [];
        $requiredClaims = [];

        if ((int) $maxAge > 0 || (null !== $maxAge && null !== $metadata->get('require_auth_time'))) {
            $requiredClaims[] = 'auth_time';
        }

        if ($fromAuthorization) {
            $requiredClaims = array_merge($requiredClaims, [
                null !== $tokenSet->getAccessToken() ? 'at_hash' : null,
                null !== $tokenSet->getCode() ? 'c_hash' : null,
            ]);

            if (array_key_exists('s_hash', $payload)) {
                $state = null !== $authSession ? $authSession->getState() : null;

                if (null === $state) {
                    throw new InvalidArgumentException('Cannot verify s_hash, "state" not provided');
                }

                $claimCheckers[] = new SHashChecker($state, $header['alg'] ?? '');
            }
        }

        $accessToken = $tokenSet->getAccessToken();
        if (null !== $accessToken) {
            $claimCheckers[] = new AtHashChecker($accessToken, $header['alg'] ?? '');
        }

        $code = $tokenSet->getCode();

        if (null !== $code) {
            $claimCheckers[] = new CHashChecker($code, $header['alg'] ?? '');
        }

        $claimCheckerManager = new ClaimCheckerManager(array_filter($claimCheckers));

        $claimCheckerManager->check($payload, array_filter($requiredClaims));
    }
}
