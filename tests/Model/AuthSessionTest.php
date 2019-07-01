<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Model;

use TMV\OpenIdClient\Model\AuthSession;
use PHPUnit\Framework\TestCase;

class AuthSessionTest extends TestCase
{

    public function testAll(): void
    {
        $session = new AuthSession();
        $this->assertCount(0, $session->all());

        $session->set('foo', 'bar');
        $this->assertCount(1, $session->all());
    }

    public function testSet(): void
    {
        $session = new AuthSession();
        $this->assertNull($session->get('foo'));

        $session->set('foo', 'bar');
        $this->assertSame('bar', $session->get('foo'));
    }

    public function testHas(): void
    {
        $session = new AuthSession();
        $this->assertFalse($session->has('foo'));

        $session->set('foo', 'bar');
        $this->assertTrue($session->has('foo'));
    }

    public function testClear(): void
    {
        $session = new AuthSession();
        $session->set('foo', 'bar');
        $this->assertCount(1, $session->all());

        $session->clear();
        $this->assertCount(0, $session->all());
    }

    public function testJsonSerialize(): void
    {
        $session = new AuthSession();
        $session->set('foo', 'bar');

        $this->assertSame(['foo' => 'bar'], $session->jsonSerialize());
    }

    public function testDel(): void
    {
        $session = new AuthSession();
        $session->set('foo', 'bar');
        $session->set('foo2', 'bar2');

        $this->assertTrue($session->has('foo'));
        $this->assertTrue($session->has('foo2'));

        $session->del('foo2');

        $this->assertTrue($session->has('foo'));
        $this->assertFalse($session->has('foo2'));
    }

    public function testGet(): void
    {
        $session = new AuthSession();

        $this->assertNull($session->get('foo'));

        $session->set('foo', 'bar');

        $this->assertSame('bar', $session->get('foo'));
    }
}
