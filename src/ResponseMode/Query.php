<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;

final class Query implements ResponseModeInterface
{
    public function getSupportedMode(): string
    {
        return 'query';
    }

    public function parseParams(ServerRequestInterface $request, ClientInterface $client): array
    {
        return $request->getQueryParams();
    }
}
