<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Exception;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\Exception\ExceptionInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RemoteException;

class OAuth2ExceptionTest extends TestCase
{
    public function testFromResponse(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getReasonPhrase()->willReturn('Bad request');
        $response->getStatusCode()->willReturn(400);

        $stream->__toString()->willReturn('{"error": "error_code"}');

        $exception = OAuth2Exception::fromResponse($response->reveal());

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame('error_code', $exception->getMessage());
        static::assertSame('error_code', $exception->getError());
        static::assertNull($exception->getDescription());
        static::assertNull($exception->getErrorUri());
    }

    public function testFromResponseComplete(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getReasonPhrase()->willReturn('Bad request');
        $response->getStatusCode()->willReturn(400);

        $stream->__toString()->willReturn('{"error": "error_code","error_description":"Error message","error_uri":"uri"}');

        $exception = OAuth2Exception::fromResponse($response->reveal());

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame('Error message (error_code)', $exception->getMessage());
        static::assertSame('error_code', $exception->getError());
        static::assertSame('Error message', $exception->getDescription());
        static::assertSame('uri', $exception->getErrorUri());
    }

    public function testFromResponseNoOAuthError(): void
    {
        $this->expectException(RemoteException::class);

        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $response->getBody()->willReturn($stream->reveal());
        $response->getReasonPhrase()->willReturn('Bad request');
        $response->getStatusCode()->willReturn(400);

        $stream->__toString()->willReturn('');

        OAuth2Exception::fromResponse($response->reveal());
    }

    public function testFromParameters(): void
    {
        $exception = OAuth2Exception::fromParameters([
            'error' => 'error_code',
            'error_description' => 'Error message',
            'error_uri' => 'uri',
        ]);

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame('Error message (error_code)', $exception->getMessage());
        static::assertSame('error_code', $exception->getError());
        static::assertSame('Error message', $exception->getDescription());
        static::assertSame('uri', $exception->getErrorUri());
    }

    public function testFromInvalidParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);

        OAuth2Exception::fromParameters([
            'error_description' => 'Error message',
            'error_uri' => 'uri',
        ]);
    }

    public function testJsonSerializer(): void
    {
        $params = [
            'error' => 'error_code',
            'error_description' => 'Error message',
            'error_uri' => 'uri',
        ];
        $exception = OAuth2Exception::fromParameters($params);

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame($params, $exception->jsonSerialize());
    }
}
