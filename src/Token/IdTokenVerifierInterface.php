<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Session\AuthSessionInterface;

interface IdTokenVerifierInterface
{
    public function validateUserinfoToken(
        ClientInterface $client,
        string $idToken,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): array;

    public function validateIdToken(
        ClientInterface $client,
        string $idToken,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): array;
}
