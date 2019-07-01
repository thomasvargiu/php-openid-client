<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Psr\Http\Message\RequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;

interface AuthMethodInterface
{
    public const TLS_METHODS = [
        'self_signed_tls_client_auth',
        'tls_client_auth',
    ];

    public function getSupportedMethod(): string;
    public function createRequest(RequestInterface $request, OpenIDClient $client, array $claims): RequestInterface;
}
