<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;

/**
 * Handle endpoint URI based on auth method
 *
 * @param OpenIDClient $client
 * @param string $endpointMetadata
 *
 * @return string
 */
function get_endpoint_uri(OpenIDClient $client, string $endpointMetadata): string
{
    $authMethod = $client->getMetadata()->get($endpointMetadata . '_auth_method');

    $endpoint = null;

    if (null !== $authMethod && false !== strpos($authMethod, 'tls_client_auth')) {
        $endpoint = $client->getIssuer()
            ->getMetadata()
            ->getMtlsEndpointAliases()['token_endpoint'] ?? null;
    }

    $endpoint = $endpoint ?: $client->getIssuer()->getMetadata()->get($endpointMetadata);

    if (! is_string($endpoint)) {
        throw new RuntimeException('Unable to retrieve the token endpoint');
    }

    return $endpoint;
}
