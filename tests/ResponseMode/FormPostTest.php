<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\ResponseMode\FormPost;

class FormPostTest extends TestCase
{
    public function testParseParams(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $serverRequest->getBody()->willReturn($stream->reveal());
        $stream->getContents()->willReturn('{"foo":"bar"}');

        $responseMode = new FormPost();

        $this->assertSame(['foo' => 'bar'], $responseMode->parseParams($serverRequest->reveal(), $client->reveal()));
    }

    public function testGetSupportedMode(): void
    {
        $responseMode = new FormPost();

        $this->assertSame('form_post', $responseMode->getSupportedMode());
    }
}
