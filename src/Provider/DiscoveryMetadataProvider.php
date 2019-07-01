<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\parseMetadataResponse;

class DiscoveryMetadataProvider
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

    public function discovery(string $uri): array
    {
        $request = $this->requestFactory->createRequest('GET', $uri);

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to fetch provider metadata', 0, $e);
        }

        $data = parseMetadataResponse($response, 200);

        if (! \array_key_exists('issuer', $data)) {
            throw new RuntimeException('Invalid metadata content, no "issuer" key found');
        }

        return $data;
    }
}
