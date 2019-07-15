<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata\Provider;

use function array_key_exists;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use function rtrim;
use function strpos;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\parse_metadata_response;

final class DiscoveryProvider implements DiscoveryProviderInterface
{
    private const OIDC_DISCOVERY = '/.well-known/openid-configuration';

    private const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';

    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var UriFactoryInterface */
    private $uriFactory;

    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
    }

    public function discovery(string $url): array
    {
        $uri = $this->uriFactory->createUri($url);
        $uriPath = $uri->getPath() ?: '/';

        if (false !== strpos($uriPath, '/.well-known/')) {
            return $this->fetchOpenIdConfiguration((string) $uri);
        }

        $uris = [
            $uri->withPath(rtrim($uriPath, '/') . self::OIDC_DISCOVERY),
            $uri->withPath('/' === $uriPath
                ? self::OAUTH2_DISCOVERY
                : self::OAUTH2_DISCOVERY . $uriPath),
        ];

        foreach ($uris as $wellKnownUri) {
            try {
                return $this->fetchOpenIdConfiguration((string) $wellKnownUri);
            } catch (RuntimeException $e) {
            }
        }

        throw new RuntimeException('Unable to fetch provider metadata');
    }

    private function fetchOpenIdConfiguration(string $uri): array
    {
        $request = $this->requestFactory->createRequest('GET', $uri)
            ->withHeader('accept', 'application/json');

        try {
            $data = parse_metadata_response($this->client->sendRequest($request));
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to fetch provider metadata', 0, $e);
        }

        if (! array_key_exists('issuer', $data)) {
            throw new RuntimeException('Invalid metadata content, no "issuer" key found');
        }

        return $data;
    }
}
