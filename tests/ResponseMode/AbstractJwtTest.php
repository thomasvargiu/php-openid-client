<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use Jose\Component\Signature\JWS;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\JWT\JWTLoader;
use TMV\OpenIdClient\ResponseMode\ResponseModeInterface;

abstract class AbstractJwtTest extends TestCase
{
    protected $jwtLoader;

    protected $baseResponseMode;

    /** @var ResponseModeInterface */
    protected $responseMode;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwtLoader = $this->prophesize(JWTLoader::class);
        $this->baseResponseMode = $this->prophesize(ResponseModeInterface::class);

        $this->responseMode = $this->createResponseMode(
            $this->jwtLoader->reveal(),
            $this->baseResponseMode->reveal()
        );
    }

    abstract protected function createResponseMode(
        JWTLoader $jwtLoader,
        ResponseModeInterface $baseResponseMode
    ): ResponseModeInterface;

    public function testGetSupportedMode(): void
    {
        $this->baseResponseMode->getSupportedMode()->willReturn('foo');

        $this->assertSame('foo.jwt', $this->responseMode->getSupportedMode());
    }

    public function testParseParams(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $serverRequest = $this->prophesize(ServerRequestInterface::class);
        $jws = $this->prophesize(JWS::class);

        $this->baseResponseMode->parseParams($serverRequest->reveal(), $client->reveal())
            ->willReturn(['response' => 'token']);

        $this->jwtLoader->load('token', $client->reveal())
            ->willReturn($jws->reveal());

        $jws->getPayload()->willReturn('{"foo":"bar"}');

        $this->assertSame(['foo' => 'bar'], $this->responseMode->parseParams($serverRequest->reveal(), $client->reveal()));
    }
}
