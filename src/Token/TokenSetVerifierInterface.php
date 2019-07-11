<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Session\AuthSessionInterface;

interface TokenSetVerifierInterface
{
    /**
     * @return IdTokenVerifierInterface
     */
    public function getIdTokenVerifier(): IdTokenVerifierInterface;

    public function validate(
        TokenSetInterface $tokenSet,
        ClientInterface $client,
        ?AuthSessionInterface $authSession = null,
        bool $fromAuthorization = true,
        ?int $maxAge = null
    ): void;
}
