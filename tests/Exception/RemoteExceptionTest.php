<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Exception;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use TMV\OpenIdClient\Exception\ExceptionInterface;
use TMV\OpenIdClient\Exception\RemoteException;

class RemoteExceptionTest extends TestCase
{
    public function testException(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $response->getReasonPhrase()->willReturn('Error message');
        $response->getStatusCode()->willReturn(400);

        $exception = new RemoteException($response->reveal());

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame('Error message', $exception->getMessage());
        static::assertSame(400, $exception->getCode());
        static::assertSame($response->reveal(), $exception->getResponse());
    }

    public function testExceptionWithCustomMessage(): void
    {
        $response = $this->prophesize(ResponseInterface::class);
        $response->getReasonPhrase()->willReturn('Error message');
        $response->getStatusCode()->willReturn(400);

        $exception = new RemoteException($response->reveal(), 'foo');

        static::assertInstanceOf(ExceptionInterface::class, $exception);
        static::assertSame('foo', $exception->getMessage());
        static::assertSame(400, $exception->getCode());
        static::assertSame($response->reveal(), $exception->getResponse());
    }
}
