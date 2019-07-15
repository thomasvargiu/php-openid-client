<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Session;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Session\AuthSession;

class AuthSessionTest extends TestCase
{
    public function testSetState(): void
    {
        $session = new AuthSession();

        static::assertNull($session->getState());

        $session->setState('foo');

        static::assertSame('foo', $session->getState());
    }

    public function testSetNonce(): void
    {
        $session = new AuthSession();

        static::assertNull($session->getNonce());

        $session->setNonce('foo');

        static::assertSame('foo', $session->getNonce());
    }

    public function testFromArray(): void
    {
        $session = AuthSession::fromArray([
            'state' => 'foo',
            'nonce' => 'bar',
        ]);

        static::assertSame('foo', $session->getState());
        static::assertSame('bar', $session->getNonce());
    }

    public function testJsonSerializer(): void
    {
        $session = AuthSession::fromArray([
            'state' => 'foo',
            'nonce' => 'bar',
        ]);

        static::assertSame([
            'state' => 'foo',
            'nonce' => 'bar',
        ], $session->jsonSerialize());
    }
}
