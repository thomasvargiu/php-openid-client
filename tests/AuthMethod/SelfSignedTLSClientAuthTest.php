<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\AuthMethod\SelfSignedTLSClientAuth;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;

class SelfSignedTLSClientAuthTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new SelfSignedTLSClientAuth($streamFactory->reveal());
        $this->assertSame('self_signed_tls_client_auth', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $streamFactory = $this->prophesize(StreamFactoryInterface::class);

        $auth = new SelfSignedTLSClientAuth($streamFactory->reveal());

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $requestWithBody = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);

        $client->getMetadata()->willReturn($metadata->reveal());
        $metadata->getClientId()->willReturn('foo');
        $metadata->getClientSecret()->shouldNotBeCalled();

        $streamFactory->createStream('foo=bar&client_id=foo')
            ->shouldBeCalled()
            ->willReturn($stream->reveal());

        $request->withBody($stream->reveal())
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
