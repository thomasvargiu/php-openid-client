<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use Jose\Component\Checker\ClaimCheckerManager;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\ClaimChecker\AtHashChecker;
use TMV\OpenIdClient\ClaimChecker\CHashChecker;
use TMV\OpenIdClient\ClaimChecker\SHashChecker;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Model\AuthSessionInterface;

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

        if (! $idToken) {
            throw new InvalidArgumentException('No id_token in token set');
        }

        $this->getIdTokenVerifier()->validateIdToken($client, $idToken, $authSession);

        $metadata = $client->getMetadata();

        $header = \json_decode(base64url_decode(\explode('.', $idToken)[0] ?? '{}'), true);
        $payload = \json_decode(base64url_decode(\explode('.', $idToken)[1] ?? '{}'), true);

        if (! \is_array($payload)) {
            throw new InvalidArgumentException('Unable to decode token payload');
        }

        $claimCheckers = [];
        $requiredClaims = [];

        if ($maxAge || (null !== $maxAge && $metadata->get('require_auth_time'))) {
            $requiredClaims[] = 'auth_time';
        }

        if ($fromAuthorization) {
            $requiredClaims = \array_merge($requiredClaims, [
                $tokenSet->getAccessToken() ? 'at_hash' : null,
                $tokenSet->getCode() ? 'c_hash' : null,
            ]);

            if (\array_key_exists('s_hash', $payload)) {
                $state = $authSession ? $authSession->getState() : null;

                if (! $state) {
                    throw new InvalidArgumentException('Cannot verify s_hash, "state" not provided');
                }

                $claimCheckers[] = new SHashChecker($state, $header['alg'] ?? '');
            }
        }

        $accessToken = $tokenSet->getAccessToken();
        if ($accessToken) {
            $claimCheckers[] = new AtHashChecker($accessToken, $header['alg'] ?? '');
        }

        $code = $tokenSet->getCode();

        if ($code) {
            $claimCheckers[] = new CHashChecker($code, $header['alg'] ?? '');
        }

        $claimCheckerManager = new ClaimCheckerManager(\array_filter($claimCheckers));

        $claimCheckerManager->check($payload, \array_filter($requiredClaims));
    }
}
