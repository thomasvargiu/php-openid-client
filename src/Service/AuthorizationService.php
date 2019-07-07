<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use JsonSerializable;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
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
     *
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

    /**
     * @param OpenIDClient $client
     * @param array<string, mixed>|null $params
     *
     * @return UriInterface
     */
    public function getAuthorizationUri(OpenIDClient $client, ?array $params = null): UriInterface
    {
        $issuerMetadata = $client->getIssuer()->getMetadata();
        $endpointUri = $issuerMetadata->getAuthorizationEndpoint();
        $params = $params ?: $client->getAuthRequest()->createParams();

        foreach ($params as $key => $value) {
            if (null === $value) {
                unset($params[$key]);
            } elseif ('claims' === $key && (\is_array($value) || $value instanceof JsonSerializable)) {
                $params['claims'] = \json_encode($value);
            } elseif (! \is_string($value)) {
                $params[$key] = (string) $value;
            }
        }

        if (empty($params['nonce']) && \in_array('id_token', \explode(' ', $params['response_type'] ?? ''), true)) {
            throw new InvalidArgumentException('nonce MUST be provided for implicit and hybrid flows');
        }

        return $this->uriFactory->createUri($endpointUri)
            ->withQuery(\http_build_query($params));
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
