<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\AuthMethod\ClientSecretBasic;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;

class ClientSecretBasicTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $auth = new ClientSecretBasic();
        $this->assertSame('client_secret_basic', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $auth = new ClientSecretBasic();

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $requestWithHeader = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);

        $client->getMetadata()->willReturn($metadata->reveal());
        $metadata->getClientId()->willReturn('foo');
        $metadata->getClientSecret()->willReturn('bar');

        $request->withHeader('Authorization', 'Basic ' . \base64_encode('foo:bar'))
            ->shouldBeCalled()
            ->willReturn($requestWithHeader->reveal());

        $requestWithHeader->getBody()
            ->willReturn($stream->reveal());

        $stream->write('foo=bar')->shouldBeCalled();

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        $this->assertSame($requestWithHeader->reveal(), $result);
    }
}
