<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\AuthMethod\ClientSecretBasic;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;

class ClientSecretBasicTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new ClientSecretBasic($streamFactory->reveal());
        $this->assertSame('client_secret_basic', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new ClientSecretBasic($streamFactory->reveal());

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $requestWithHeader = $this->prophesize(RequestInterface::class);
        $requestWithBody = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);

        $client->getMetadata()->willReturn($metadata->reveal());
        $metadata->getClientId()->willReturn('foo');
        $metadata->getClientSecret()->willReturn('bar');

        $streamFactory->createStream('foo=bar')
            ->shouldBeCalled()
            ->willReturn($stream->reveal());

        $request->withHeader('Authentication', 'Basic ' . \base64_encode('foo:bar'))
            ->shouldBeCalled()
            ->willReturn($requestWithHeader->reveal());

        $requestWithHeader->withBody($stream->reveal())
            ->shouldBeCalled()
            ->willReturn($requestWithBody->reveal());

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        $this->assertSame($requestWithBody->reveal(), $result);
    }
}
