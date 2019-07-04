<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\AuthMethod\None;
use TMV\OpenIdClient\ClientInterface;

class NoneTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new None($streamFactory->reveal());
        $this->assertSame('none', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new None($streamFactory->reveal());

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $requestWithBody = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $streamFactory->createStream('foo=bar')
            ->shouldBeCalled()
            ->willReturn($stream->reveal());

        $request->withBody($stream->reveal())
            ->shouldBeCalled()
            ->willReturn($requestWithBody->reveal());

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        $this->assertSame($requestWithBody->reveal(), $result);
    }
}
