<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ResponseMode;

use TMV\OpenIdClient\JWT\JWTLoader;
use TMV\OpenIdClient\ResponseMode\FormPostJwt;
use TMV\OpenIdClient\ResponseMode\ResponseModeInterface;

class FormPostJwtTest extends AbstractJwtTest
{
    protected function createResponseMode(
        JWTLoader $jwtLoader,
        ResponseModeInterface $baseResponseMode
    ): ResponseModeInterface
    {
        return new FormPostJwt($jwtLoader, $baseResponseMode);
    }

    public function testGetSupportedModeWithDefaultBaseMode(): void
    {
        $jwtLoader = $this->prophesize(JWTLoader::class);

        $responseMode = new FormPostJwt(
            $jwtLoader->reveal()
        );

        $this->assertSame('form_post.jwt', $responseMode->getSupportedMode());
    }
}
