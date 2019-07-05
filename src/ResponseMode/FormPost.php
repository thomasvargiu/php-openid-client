<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;

final class FormPost implements ResponseModeInterface
{
    public function getSupportedMode(): string
    {
        return 'form_post';
    }

    public function parseParams(ServerRequestInterface $request, ClientInterface $client): array
    {
        $data = $request->getParsedBody();

        if (! \is_array($data)) {
            throw new RuntimeException('Unable to decode response body');
        }

        return $data;
    }
}
