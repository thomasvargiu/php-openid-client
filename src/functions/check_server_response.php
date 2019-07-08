<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Psr\Http\Message\ResponseInterface;
use TMV\OpenIdClient\Exception\OAuth2Exception;

/**
 * @param ResponseInterface $response
 * @param int|null $expectedCode
 */
function check_server_response(ResponseInterface $response, ?int $expectedCode = null): void
{
    if (! $expectedCode && $response->getStatusCode() >= 400) {
        throw OAuth2Exception::fromResponse($response);
    }

    if ($expectedCode && $expectedCode !== $response->getStatusCode()) {
        throw OAuth2Exception::fromResponse($response);
    }
}
