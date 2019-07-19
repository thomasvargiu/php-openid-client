<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Client;

use Jose\Component\Core\JWKSet;
use Psr\Http\Client\ClientInterface as HttpClient;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;

interface ClientInterface
{
    public function getIssuer(): IssuerInterface;

    public function getMetadata(): ClientMetadataInterface;

    public function getJwks(): JWKSet;

    public function getAuthMethodFactory(): AuthMethodFactoryInterface;

    public function getHttpClient(): ?HttpClient;
}
