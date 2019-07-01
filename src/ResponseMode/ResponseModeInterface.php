<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;

interface ResponseModeInterface
{
    public function getSupportedMode(): string;
    public function parseParams(ServerRequestInterface $request, ClientInterface $client): array;
}
