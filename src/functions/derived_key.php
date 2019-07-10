<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWK;

function derived_key(string $secret, int $length): JWK
{
    $hash = \substr(\hash('sha256', $secret, true), 0, $length / 8);

    return new JWK([
        'k' => base64url_encode($hash),
        'kty' => 'oct',
    ]);
}
