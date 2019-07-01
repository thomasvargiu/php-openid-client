<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

final class TLSClientAuth extends AbstractTLS
{
    public function getSupportedMethod(): string
    {
        return 'tls_client_auth';
    }
}
