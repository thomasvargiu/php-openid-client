<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\functions;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RemoteException;
use function TMV\OpenIdClient\parse_metadata_response;

class ParseMetadataResponseTest extends TestCase
{
    public function testHappyPath(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('{"foo":"bar"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);

        $data = parse_metadata_response($response->reveal());

        static::assertSame(['foo' => 'bar'], $data);
    }

    public function testWithInvalidContent(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid metadata content');

        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('{"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->willReturn(200);

        parse_metadata_response($response->reveal());
    }

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

        parse_metadata_response($response->reveal());
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

        parse_metadata_response($response->reveal());
    }

    public function testErrorStatusCodeWithExpectedCode(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $stream->__toString()->willReturn('{"error":"foo"}');
        $response->getBody()->willReturn($stream->reveal());
        $response->getStatusCode()->shouldBeCalled()->willReturn(400);

        parse_metadata_response($response->reveal(), 400);
    }
}
