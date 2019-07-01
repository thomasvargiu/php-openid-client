<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Psr\Http\Message\ResponseInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

/**
 * @param ResponseInterface $response
 * @param int|null $expectedCode
 * @return array<string, mixed>
 */
function parseMetadataResponse(ResponseInterface $response, ?int $expectedCode = null): array
{
    checkServerResponse($response, $expectedCode);

    /** @var boolean|array<string, mixed> $data */
    $data = \json_decode($response->getBody()->getContents(), true);

    if (! \is_array($data)) {
        throw new InvalidArgumentException('Invalid metadata content');
    }

    return $data;
}