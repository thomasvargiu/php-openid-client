<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\AuthMethod;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use TMV\OpenIdClient\AuthMethod\ClientSecretPost;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;

class ClientSecretPostTest extends TestCase
{
    public function testGetSupportedMethod(): void
    {
        $auth = new ClientSecretPost();
        $this->assertSame('client_secret_post', $auth->getSupportedMethod());
    }

    public function testCreateRequest(): void
    {
        $auth = new ClientSecretPost();

        $stream = $this->prophesize(StreamInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);

        $client->getMetadata()->willReturn($metadata->reveal());
        $metadata->getClientId()->willReturn('foo');
        $metadata->getClientSecret()->willReturn('bar');

        $stream->write('foo=bar&client_id=foo&client_secret=bar')
            ->shouldBeCalled();

        $request->getBody()->willReturn($stream);

        $result = $auth->createRequest(
            $request->reveal(),
            $client->reveal(),
            ['foo' => 'bar']
        );

        $this->assertSame($request->reveal(), $result);
    }
}
