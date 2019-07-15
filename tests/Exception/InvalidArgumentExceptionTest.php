<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Exception;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Exception\ExceptionInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

class InvalidArgumentExceptionTest extends TestCase
{
    public function testException(): void
    {
        $exception = new InvalidArgumentException();
        static::assertInstanceOf(ExceptionInterface::class, $exception);
    }
}
