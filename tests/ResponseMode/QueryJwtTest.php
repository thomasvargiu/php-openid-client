<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use TMV\OpenIdClient\JWT\JWTLoader;
use TMV\OpenIdClient\ResponseMode\QueryJwt;
use TMV\OpenIdClient\ResponseMode\ResponseModeInterface;

class QueryJwtTest extends AbstractJwtTest
{
    protected function createResponseMode(
        JWTLoader $jwtLoader,
        ResponseModeInterface $baseResponseMode
    ): ResponseModeInterface {
        return new QueryJwt($jwtLoader, $baseResponseMode);
    }

    public function testGetSupportedModeWithDefaultBaseMode(): void
    {
        $jwtLoader = $this->prophesize(JWTLoader::class);

        $responseMode = new QueryJwt(
            $jwtLoader->reveal()
        );

        $this->assertSame('query.jwt', $responseMode->getSupportedMode());
    }
}
