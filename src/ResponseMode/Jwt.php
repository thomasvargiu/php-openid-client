<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use TMV\OpenIdClient\JWT\JWTLoader;

final class Jwt extends AbstractJwt
{
    public function __construct(
        JWTLoader $jwtLoader,
        ?ResponseModeInterface $baseStrategy = null
    ) {
        parent::__construct(
            $jwtLoader,
            $baseStrategy ?: new Query()
        );
    }

    public function getSupportedMode(): string
    {
        return 'jwt';
    }
}
