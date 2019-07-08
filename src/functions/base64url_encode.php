<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

function base64url_encode(string $data): string
{
    return \rtrim(\strtr(\base64_encode($data), '+/', '-_'), '=');
}
