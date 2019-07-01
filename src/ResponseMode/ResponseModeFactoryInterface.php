<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

interface ResponseModeFactoryInterface
{
    public function create(string $responseMode): ResponseModeInterface;
}
