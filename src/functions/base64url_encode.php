<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use function base64_encode;
use function rtrim;
use function strtr;

function base64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
