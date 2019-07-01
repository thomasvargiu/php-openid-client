<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use TMV\OpenIdClient\ResponseMode\ResponseModeFactoryInterface;
use TMV\OpenIdClient\ResponseMode\ResponseModeInterface;
use TMV\OpenIdClient\ResponseMode\ResponseModeProvider;
use PHPUnit\Framework\TestCase;

class ResponseModeProviderTest extends TestCase
{

    public function testWithFragment(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('GET');
        $serverRequest->getUri()->willReturn($uri->reveal());
        $uri->getFragment()->willReturn('foo=bar');

        $factory->create('fragment')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }

    public function testWithFragmentJwt(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('GET');
        $serverRequest->getUri()->willReturn($uri->reveal());
        $uri->getFragment()->willReturn('response=bar');

        $factory->create('fragment.jwt')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }

    public function testWithQuery(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('GET');
        $serverRequest->getUri()->willReturn($uri->reveal());
        $serverRequest->getQueryParams()->shouldBeCalled()->willReturn([]);
        $uri->getFragment()->willReturn('');

        $factory->create('query')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }

    public function testWithQueryJwt(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('GET');
        $serverRequest->getUri()->willReturn($uri->reveal());
        $serverRequest->getQueryParams()->shouldBeCalled()->willReturn(['response' => '']);
        $uri->getFragment()->willReturn('');

        $factory->create('query.jwt')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }

    public function testWithFormPost(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('POST');
        $serverRequest->getParsedBody()->shouldBeCalled()->willReturn([]);

        $factory->create('form_post')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }

    public function testWithFormPostJwt(): void
    {
        $factory = $this->prophesize(ResponseModeFactoryInterface::class);

        $provider = new ResponseModeProvider($factory->reveal());

        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $responseMode = $this->prophesize(ResponseModeInterface::class);

        $serverRequest->getMethod()->willReturn('POST');
        $serverRequest->getParsedBody()->shouldBeCalled()->willReturn(['response' => 'foo']);

        $factory->create('form_post.jwt')->willReturn($responseMode->reveal());

        $this->assertSame($responseMode->reveal(), $provider->getResponseMode($serverRequest->reveal()));
    }
}
