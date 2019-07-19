<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function TMV\OpenIdClient\check_server_response;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\get_endpoint_uri;

/**
 * RFC 7009 Token Revocation
 *
 * @link https://tools.ietf.org/html/rfc7009 RFC 7009
 */
class RevocationService
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

    public function revoke(OpenIDClient $client, string $token, array $params = []): void
    {
        $endpointUri = get_endpoint_uri($client, 'revocation_endpoint');

        $authMethod = $client->getAuthMethodFactory()
            ->create($client->getMetadata()->getRevocationEndpointAuthMethod());

        $tokenRequest = $this->requestFactory->createRequest('POST', $endpointUri)
            ->withHeader('content-type', 'application/x-www-form-urlencoded');

        $tokenRequest = $authMethod->createRequest($tokenRequest, $client, $params);
        $tokenRequest->getBody()->write(http_build_query(array_merge($params, [
            'token' => $token,
        ])));

        $httpClient = $client->getHttpClient() ?: $this->client;

        try {
            $response = $httpClient->sendRequest($tokenRequest);
            check_server_response($response, 200);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get revocation response', 0, $e);
        }
    }
}
