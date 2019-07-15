<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\AuthMethod\None;
use TMV\OpenIdClient\Client\ClientInterface;

class NoneTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $auth = new None();
        static::assertSame('none', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $auth = new None();

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $stream->write('foo=bar')->shouldBeCalled();

        $request->getBody()->willReturn($stream->reveal());

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        static::assertSame($request->reveal(), $result);
    }
}
