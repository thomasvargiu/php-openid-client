<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use TMV\OpenIdClient\AuthMethod\AuthMethodFactory;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\AuthMethod\AuthMethodInterface;

class AuthMethodFactoryTest extends TestCase
{
    public function testFactory(): void
    {
        $authMethod1 = $this->prophesize(AuthMethodInterface::class);
        $authMethod2 = $this->prophesize(AuthMethodInterface::class);

        $authMethod1->getSupportedMethod()->willReturn('foo');
        $authMethod2->getSupportedMethod()->willReturn('bar');

        $factory = new AuthMethodFactory([
            $authMethod1->reveal(),
            $authMethod2->reveal(),
        ]);

        $this->assertCount(2, $factory->all());
        $this->assertSame($authMethod1->reveal(), $factory->create('foo'));
        $this->assertSame($authMethod2->reveal(), $factory->create('bar'));
    }
}
