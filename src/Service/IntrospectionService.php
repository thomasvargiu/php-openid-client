<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\get_endpoint_uri;
use function TMV\OpenIdClient\parse_metadata_response;

/**
 * RFC 7662 Token Introspection
 *
 * @link https://tools.ietf.org/html/rfc7662 RFC 7662
 */
class IntrospectionService
{
    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
    }

    public function introspect(OpenIDClient $client, string $token, array $params = []): array
    {
        $endpointUri = get_endpoint_uri($client, 'introspection_endpoint');

        $authMethod = $client->getAuthMethodFactory()
            ->create($client->getMetadata()->getRevocationEndpointAuthMethod());

        $tokenRequest = $this->requestFactory->createRequest('POST', $endpointUri)
            ->withHeader('content-type', 'application/x-www-form-urlencoded');

        $tokenRequest = $authMethod->createRequest($tokenRequest, $client, $params);
        $tokenRequest->getBody()->write(http_build_query(array_merge($params, [
            'token' => $token,
        ])));

        try {
            $response = $this->client->sendRequest($tokenRequest);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get revocation response', 0, $e);
        }

        return parse_metadata_response($response, 200);
    }
}
