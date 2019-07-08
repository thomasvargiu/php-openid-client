<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;

interface ClientInterface
{
    public function getIssuer(): IssuerInterface;

    public function getMetadata(): ClientMetadataInterface;

    public function getJWKS(): JWKSet;

    public function getAuthMethodFactory(): AuthMethodFactoryInterface;

    public function getTokenEndpoint(): string;

    public function getRevocationEndpoint(): ?string;

    public function getIntrospectionEndpoint(): ?string;

    public function getUserinfoEndpoint(): ?string;
}
