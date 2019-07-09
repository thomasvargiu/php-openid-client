<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\Exception\RuntimeException;

/**
 * @param ServerRequestInterface $serverRequest
 *
 * @return array<string, mixed>
 */
function parse_callback_params(ServerRequestInterface $serverRequest): array
{
    $method = \strtoupper($serverRequest->getMethod());

    if ('POST' === $method) {
        $params = $serverRequest->getParsedBody();

        if (! \is_array($params)) {
            throw new RuntimeException('Invalid parsed body');
        }

        return $params;
    }

    if ('GET' !== $method) {
        throw new RuntimeException('Invalid callback method');
    }

    if ($serverRequest->getUri()->getFragment()) {
        \parse_str($serverRequest->getUri()->getFragment(), $params);

        return $params;
    }

    \parse_str($serverRequest->getUri()->getQuery(), $params);

    return $params;
}
