<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\functions;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use function TMV\OpenIdClient\checkServerResponse;
use PHPUnit\Framework\TestCase;
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

        $stream->getContents()->willReturn('');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(400);
        $response->getReasonPhrase()->willReturn('Error');

        checkServerResponse($response->reveal());
    }

    public function testErrorStatusCodeWithOAuth2Error(): void
    {
        $this->expectException(OAuth2Exception::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('foo');

        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->getContents()->willReturn('{"error":"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(400);
        $response->getReasonPhrase()->shouldNotBeCalled();

        checkServerResponse($response->reveal());
    }

    public function testErrorStatusCodeWithExpectedCode(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->getContents()->willReturn('{"error":"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->shouldBeCalled()->willReturn(400);

        checkServerResponse($response->reveal(), 400);
    }
}
