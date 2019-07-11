<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;

interface IssuerInterface
{
    public function getMetadata(): IssuerMetadataInterface;

    public function getJwks(): JWKSet;

    /**
     * Force update of issuer JWKs
     */
    public function updateJwks(): void;
}
