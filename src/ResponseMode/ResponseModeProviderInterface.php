<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;

interface ResponseModeProviderInterface
{
    public function getResponseMode(ServerRequestInterface $serverRequest): ResponseModeInterface;
}
