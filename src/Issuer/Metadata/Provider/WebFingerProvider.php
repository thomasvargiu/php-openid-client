<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata\Provider;

use function array_key_exists;
use function explode;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use function http_build_query;
use function is_array;
use function is_string;
use function parse_url;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use function strpos;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\normalize_webfinger;
use function TMV\OpenIdClient\parse_metadata_response;

final class WebFingerProvider implements WebFingerProviderInterface
{
    private const OIDC_DISCOVERY = '/.well-known/openid-configuration';

    private const WEBFINGER = '/.well-known/webfinger';

    private const REL = 'http://openid.net/specs/connect/1.0/issuer';

    private const AAD_MULTITENANT_DISCOVERY = 'https://login.microsoftonline.com/common/v2.0$' . self::OIDC_DISCOVERY;

    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var UriFactoryInterface */
    private $uriFactory;

    /** @var DiscoveryProviderInterface */
    private $discoveryProvider;

    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null,
        ?DiscoveryProviderInterface $discoveryProvider = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
        $this->discoveryProvider = $discoveryProvider ?: new DiscoveryProvider(
            $this->client,
            $this->requestFactory,
            $this->uriFactory
        );
    }

    public function fetch(string $resource): array
    {
        $resource = normalize_webfinger($resource);
        $parsedUrl = parse_url(
            false !== strpos($resource, '@')
                ? 'https://' . explode('@', $resource)[1]
                : $resource
        );

        if (! is_array($parsedUrl) || ! array_key_exists('host', $parsedUrl)) {
            throw new RuntimeException('Unable to parse resource');
        }

        $host = $parsedUrl['host'];

        /** @var string|int|null $port */
        $port = $parsedUrl['port'] ?? null;

        if ((int) $port > 0) {
            $host .= ':' . $port;
        }

        $webFingerUrl = $this->uriFactory->createUri('https://' . $host . self::WEBFINGER)
            ->withQuery(http_build_query(['resource' => $resource, 'rel' => self::REL]));

        $request = $this->requestFactory->createRequest('GET', $webFingerUrl)
            ->withHeader('accept', 'application/json');

        try {
            $data = parse_metadata_response($this->client->sendRequest($request));
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to fetch provider metadata', 0, $e);
        }

        $links = $data['links'] ?? [];
        $href = null;
        foreach ($links as $link) {
            if (! is_array($link)) {
                continue;
            }

            if (($link['rel'] ?? null) !== self::REL) {
                continue;
            }

            if (! array_key_exists('href', $link)) {
                continue;
            }

            $href = $link['href'];
        }

        if (! is_string($href) || 0 !== strpos($href, 'https://')) {
            throw new InvalidArgumentException('Invalid issuer location');
        }

        $metadata = $this->discoveryProvider->discovery($href);

        if (($metadata['issuer'] ?? null) !== $href) {
            throw new RuntimeException('Discovered issuer mismatch');
        }

        return $metadata;
    }
}
