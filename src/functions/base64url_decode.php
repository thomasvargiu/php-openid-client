<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use TMV\OpenIdClient\Exception\RuntimeException;

function base64url_decode(string $data): string
{
    $decoded = \base64_decode(\str_pad(\strtr($data, '-_', '+/'), \strlen($data) % 4, '='));

    if (! $decoded) {
        throw new RuntimeException('Unable to base64url_decode');
    }

    return $decoded;
}
