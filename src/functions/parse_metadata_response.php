<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Psr\Http\Message\ResponseInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

/**
 * @param ResponseInterface $response
 * @param int|null $expectedCode
 *
 * @return array<string, mixed>
 */
function parse_metadata_response(ResponseInterface $response, ?int $expectedCode = null): array
{
    check_server_response($response, $expectedCode);

    /** @var bool|array<string, mixed> $data */
    $data = \json_decode((string) $response->getBody(), true);

    if (! \is_array($data)) {
        throw new InvalidArgumentException('Invalid metadata content');
    }

    return $data;
}
