<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Psr\Http\Message\RequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;

final class None implements AuthMethodInterface
{
    public function getSupportedMethod(): string
    {
        return 'none';
    }

    public function createRequest(
        RequestInterface $request,
        OpenIDClient $client,
        array $claims
    ): RequestInterface {
        $request->getBody()->write(\http_build_query($claims));

        return $request;
    }
}
