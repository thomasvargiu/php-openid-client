<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWK;

function derived_key(string $secret, int $length): JWK
{
    $hash = \substr(\hash('sha256', $secret, true), $length);

    return new JWK([
        'k' => base64url_encode($hash),
        'kty' => 'oct',
    ]);
}
