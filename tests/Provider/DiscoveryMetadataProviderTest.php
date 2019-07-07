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

        $request1 = $this->prophesize(RequestInterface::class);
        $request2 = $this->prophesize(RequestInterface::class);
        $request3 = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);
        $stream->__toString()->willReturn('{"issuer":"foo"}');

        $request1->withHeader('accept', 'application/json')
            ->shouldBeCalled()
            ->willReturn($request2->reveal());

        $request2->withHeader('content-type', 'application/json')
            ->shouldBeCalled()
            ->willReturn($request3->reveal());

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request1->reveal());

        $client->sendRequest($request3->reveal())
            ->willReturn($response->reveal());

        $this->assertSame(['issuer' => 'foo'], $provider->discovery($uri));
    }
}
