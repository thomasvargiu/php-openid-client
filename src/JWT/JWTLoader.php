<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\JWT;

use Jose\Component\Signature\JWS;
use TMV\OpenIdClient\ClientInterface;

interface JWTLoader
{
    public function load(string $content, ClientInterface $client): JWS;
}
