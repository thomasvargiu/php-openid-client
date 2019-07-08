<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Model;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Model\AuthSession;

class AuthSessionTest extends TestCase
{
    public function testSetState(): void
    {
        $session = new AuthSession();

        $this->assertNull($session->getState());

        $session->setState('foo');

        $this->assertSame('foo', $session->getState());
    }

    public function testSetNonce(): void
    {
        $session = new AuthSession();

        $this->assertNull($session->getNonce());

        $session->setNonce('foo');

        $this->assertSame('foo', $session->getNonce());
    }
}
