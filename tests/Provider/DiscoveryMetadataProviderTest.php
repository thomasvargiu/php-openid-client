<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Provider;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProvider;

class DiscoveryMetadataProviderTest extends TestCase
{
    public function testDiscovery(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $uri = 'https://example.com';
        $provider = new DiscoveryMetadataProvider(
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $request1 = $this->prophesize(RequestInterface::class);
        $request2 = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);
        $stream->__toString()->willReturn('{"issuer":"foo"}');

        $request1->withHeader('accept', 'application/json')
            ->shouldBeCalled()
            ->willReturn($request2->reveal());

        $uri1 = $this->prophesize(UriInterface::class);
        $uri2 = $this->prophesize(UriInterface::class);
        $uri3 = $this->prophesize(UriInterface::class);

        $uri1->getPath()->willReturn('/');
        $uri1->withPath('/.well-known/openid-configuration')
            ->willReturn($uri2->reveal());
        $uri1->withPath('/.well-known/oauth-authorization-server')
            ->willReturn($uri3->reveal());

        $uri2->__toString()->willReturn('uri2');
        $uri3->__toString()->willReturn('uri3');

        $requestFactory->createRequest('GET', 'uri2')
            ->willReturn($request1->reveal());

        $client->sendRequest($request2->reveal())
            ->willReturn($response->reveal());

        $uriFactory->createUri($uri)->willReturn($uri1->reveal());

        $this->assertSame(['issuer' => 'foo'], $provider->discovery($uri));
    }

    public function testDiscoveryWithWellKnown(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $uri = 'https://example.com/.well-known/openid-configuration';
        $provider = new DiscoveryMetadataProvider(
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $request1 = $this->prophesize(RequestInterface::class);
        $request2 = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);
        $stream->__toString()->willReturn('{"issuer":"foo"}');

        $request1->withHeader('accept', 'application/json')
            ->shouldBeCalled()
            ->willReturn($request2->reveal());

        $uri1 = $this->prophesize(UriInterface::class);

        $uri1->getPath()->willReturn('/.well-known/openid-configuration');

        $uri1->__toString()->willReturn('https://example.com/.well-known/openid-configuration');

        $requestFactory->createRequest('GET', 'https://example.com/.well-known/openid-configuration')
            ->willReturn($request1->reveal());

        $client->sendRequest($request2->reveal())
            ->willReturn($response->reveal());

        $uriFactory->createUri($uri)->willReturn($uri1->reveal());

        $this->assertSame(['issuer' => 'foo'], $provider->discovery($uri));
    }
}
