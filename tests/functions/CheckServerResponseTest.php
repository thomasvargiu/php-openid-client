<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\functions;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use function TMV\OpenIdClient\check_server_response;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RemoteException;

class CheckServerResponseTest extends TestCase
{
    public function testErrorStatusCode(): void
    {
        $this->expectException(RemoteException::class);
        $this->expectExceptionCode(400);
        $this->expectExceptionMessage('Error');

        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(400);
        $response->getReasonPhrase()->willReturn('Error');

        check_server_response($response->reveal());
    }

    public function testErrorStatusCodeWithOAuth2Error(): void
    {
        $this->expectException(OAuth2Exception::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('foo');

        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('{"error":"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(400);
        $response->getReasonPhrase()->shouldNotBeCalled();

        check_server_response($response->reveal());
    }

    public function testErrorStatusCodeWithExpectedCode(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('{"error":"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->shouldBeCalled()->willReturn(400);

        check_server_response($response->reveal(), 400);
    }
}
