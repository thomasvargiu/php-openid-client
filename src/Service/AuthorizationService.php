<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use TMV\OpenIdClient\Authorization\AuthRequestInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use function TMV\OpenIdClient\parseMetadataResponse;

class AuthorizationService
{
    /** @var ClientInterface */
    private $client;
    /** @var RequestFactoryInterface */
    private $requestFactory;
    /** @var UriFactoryInterface */
    private $uriFactory;

    /**
     * AuthorizationService constructor.
     * @param null|ClientInterface $client
     * @param null|RequestFactoryInterface $requestFactory
     * @param null|UriFactoryInterface $uriFactory
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
    }

    public function getAuthorizationUri(OpenIDClient $client, ?AuthRequestInterface $authRequest = null): UriInterface
    {
        $issuerMetadata = $client->getIssuer()->getMetadata();
        $endpointUri = $issuerMetadata->getAuthorizationEndpoint();
        $authRequest = $authRequest ?: $client->getAuthRequest();

        return $this->uriFactory->createUri($endpointUri)
            ->withQuery(\http_build_query($authRequest->createParams()));
    }

    public function fetchTokenFromCode(OpenIDClient $client, string $code): array
    {
        $claims = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->getAuthRequest()->getRedirectUri(),
        ];

        $authMethod = $client->getAuthMethodFactory()
            ->create($client->getMetadata()->getTokenEndpointAuthMethod());

        $tokenRequest = $this->requestFactory->createRequest('POST', $client->getTokenEndpoint())
            ->withHeader('content-type', 'application/x-www-form-urlencoded');

        $tokenRequest = $authMethod->createRequest($tokenRequest, $client, $claims);

        try {
            $response = $this->client->sendRequest($tokenRequest);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get token response', 0, $e);
        }

        return parseMetadataResponse($response);
    }
}
