<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;

class Issuer implements IssuerInterface
{
    /** @var IssuerMetadataInterface */
    private $metadata;
    /** @var JWKSet */
    private $jwks;

    /**
     * Issuer constructor.
     * @param IssuerMetadataInterface $metadata
     * @param JWKSet $jwks
     */
    public function __construct(IssuerMetadataInterface $metadata, JWKSet $jwks)
    {
        $this->metadata = $metadata;
        $this->jwks = $jwks;
    }

    public function getMetadata(): IssuerMetadataInterface
    {
        return $this->metadata;
    }

    /**
     * @return JWKSet
     */
    public function getJwks(): JWKSet
    {
        return $this->jwks;
    }
}
