<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Client;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactory;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\AuthMethod\ClientSecretBasic;
use TMV\OpenIdClient\AuthMethod\ClientSecretJwt;
use TMV\OpenIdClient\AuthMethod\ClientSecretPost;
use TMV\OpenIdClient\AuthMethod\None;
use TMV\OpenIdClient\AuthMethod\PrivateKeyJwt;
use TMV\OpenIdClient\AuthMethod\SelfSignedTLSClientAuth;
use TMV\OpenIdClient\AuthMethod\TLSClientAuth;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;

final class Client implements ClientInterface
{
    /** @var IssuerInterface */
    private $issuer;

    /** @var ClientMetadataInterface */
    private $metadata;

    /** @var JWKSet */
    private $jwks;

    /** @var AuthMethodFactoryInterface */
    private $authMethodFactory;

    /**
     * Client constructor.
     *
     * @param IssuerInterface $issuer
     * @param ClientMetadataInterface $metadata
     * @param null|JWKSet $jwks
     * @param null|AuthMethodFactoryInterface $authMethodFactory
     */
    public function __construct(
        IssuerInterface $issuer,
        ClientMetadataInterface $metadata,
        ?JWKSet $jwks = null,
        ?AuthMethodFactoryInterface $authMethodFactory = null
    ) {
        $this->issuer = $issuer;
        $this->metadata = $metadata;
        $this->jwks = $jwks ?: new JWKSet([]);
        $this->authMethodFactory = $authMethodFactory ?: new AuthMethodFactory([
            new ClientSecretBasic(),
            new ClientSecretJwt(),
            new ClientSecretPost(),
            new None(),
            new PrivateKeyJwt(),
            new TLSClientAuth(),
            new SelfSignedTLSClientAuth(),
        ]);
    }

    /**
     * @return IssuerInterface
     */
    public function getIssuer(): IssuerInterface
    {
        return $this->issuer;
    }

    public function getMetadata(): ClientMetadataInterface
    {
        return $this->metadata;
    }

    public function getJwks(): JWKSet
    {
        return $this->jwks;
    }

    /**
     * @return AuthMethodFactoryInterface
     */
    public function getAuthMethodFactory(): AuthMethodFactoryInterface
    {
        return $this->authMethodFactory;
    }
}
