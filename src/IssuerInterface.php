<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;

interface IssuerInterface
{
    public function getMetadata(): IssuerMetadataInterface;

    public function getJwks(): JWKSet;

    /**
     * Force update of issuer JWKs
     */
    public function updateJwks(): void;
}
