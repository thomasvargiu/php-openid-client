<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Provider;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\parse_metadata_response;

class DiscoveryMetadataProvider implements DiscoveryMetadataProviderInterface
{
    private const OIDC_DISCOVERY = '/.well-known/openid-configuration';

    private const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';

    private const WEBFINGER = '/.well-known/webfinger';

    private const REL = 'http://openid.net/specs/connect/1.0/issuer';

    private const AAD_MULTITENANT_DISCOVERY = 'https://login.microsoftonline.com/common/v2.0$' . self::OIDC_DISCOVERY;

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

    public function webfinger(string $resource): array
    {
        $uri = $this->uriFactory->createUri($resource);
        $webfingerUrl = $this->uriFactory->createUri('https://' . $uri->getHost() . ':' . $uri->getPort() . self::WEBFINGER)
            ->withQuery(\http_build_query(['resource' => (string) $uri, 'rel' => self::REL]));

        $request = $this->requestFactory->createRequest('GET', $webfingerUrl)
            ->withHeader('accept', 'application/json');

        try {
            $data = parse_metadata_response($this->client->sendRequest($request));
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to fetch provider metadata', 0, $e);
        }

        $links = $data['links'] ?? [];
        $href = null;
        foreach ($links as $link) {
            if (! \is_array($link)) {
                continue;
            }

            if (($link['rel'] ?? null) !== self::REL) {
                continue;
            }

            if (! \array_key_exists('href', $link)) {
                continue;
            }

            $href = $link['href'];
        }

        if (! \is_string($href) || 0 !== \strpos($href, 'https://')) {
            throw new InvalidArgumentException('Invalid issuer location');
        }

        $metadata = $this->discovery($href);

        if ($metadata['issuer'] !== $href) {
            throw new RuntimeException('Discovered issuer mismatch');
        }

        return $metadata;
    }

    public function discovery(string $url): array
    {
        $uri = $this->uriFactory->createUri($url);
        $uriPath = $uri->getPath() ?: '/';

        if (false !== \strpos($uriPath, '/.well-known/')) {
            return $this->fetchOpenIdConfiguration((string) $uri);
        }

        $uris = [
            $uri->withPath(\rtrim($uriPath, '/') . self::OIDC_DISCOVERY),
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

        if (! \array_key_exists('issuer', $data)) {
            throw new RuntimeException('Invalid metadata content, no "issuer" key found');
        }

        return $data;
    }
}
