<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Provider;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProvider;

class DiscoveryMetadataProviderTest extends TestCase
{
    public function testDiscovery(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);

        $uri = 'https://example.com';
        $provider = new DiscoveryMetadataProvider(
            $client->reveal(),
            $requestFactory->reveal()
        );

        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);
        $stream->getContents()->willReturn('{"issuer":"foo"}');

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());

        $client->sendRequest($request->reveal())
            ->willReturn($response->reveal());

        $this->assertSame(['issuer' => 'foo'], $provider->discovery($uri));
    }
}
