<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\ResponseMode\Query;

class QueryTest extends TestCase
{
    public function testParseParams(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $serverRequest = $this->prophesize(ServerRequestInterface::class);

        $serverRequest->getQueryParams()->willReturn(['foo' => 'bar']);

        $responseMode = new Query();

        $this->assertSame(['foo' => 'bar'], $responseMode->parseParams($serverRequest->reveal(), $client->reveal()));
    }

    public function testGetSupportedMode(): void
    {
        $responseMode = new Query();

        $this->assertSame('query', $responseMode->getSupportedMode());
    }
}
