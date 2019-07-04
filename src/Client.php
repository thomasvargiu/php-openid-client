<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactory;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\AuthMethod\AuthMethodInterface;
use TMV\OpenIdClient\AuthMethod\ClientSecretBasic;
use TMV\OpenIdClient\Authorization\AuthRequestInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Model\ClientMetadataInterface;
use TMV\OpenIdClient\ResponseMode\FormPost;
use TMV\OpenIdClient\ResponseMode\Query;
use TMV\OpenIdClient\ResponseMode\ResponseModeFactory;
use TMV\OpenIdClient\ResponseMode\ResponseModeFactoryInterface;

class Client implements ClientInterface
{
    /** @var IssuerInterface */
    private $issuer;

    /** @var ClientMetadataInterface */
    private $metadata;

    /** @var JWKSet */
    private $jwks;

    /** @var AuthRequestInterface */
    private $authRequest;

    /** @var AuthMethodFactoryInterface */
    private $authMethodFactory;

    /** @var ResponseModeFactoryInterface */
    private $responseModeFactory;

    /**
     * Client constructor.
     *
     * @param IssuerInterface $issuer
     * @param ClientMetadataInterface $metadata
     * @param JWKSet $jwks
     * @param AuthRequestInterface $authRequest
     * @param null|AuthMethodFactoryInterface $authMethodFactory
     * @param null|ResponseModeFactoryInterface $responseModeFactory
     */
    public function __construct(
        IssuerInterface $issuer,
        ClientMetadataInterface $metadata,
        JWKSet $jwks,
        AuthRequestInterface $authRequest,
        ?AuthMethodFactoryInterface $authMethodFactory = null,
        ?ResponseModeFactoryInterface $responseModeFactory = null
    ) {
        $this->issuer = $issuer;
        $this->metadata = $metadata;
        $this->jwks = $jwks;
        $this->authRequest = $authRequest;
        $this->authMethodFactory = $authMethodFactory ?: new AuthMethodFactory([
            new ClientSecretBasic(),
        ]);
        $this->responseModeFactory = $responseModeFactory ?: new ResponseModeFactory([
            new Query(),
            new FormPost(),
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
     * @return AuthRequestInterface
     */
    public function getAuthRequest(): AuthRequestInterface
    {
        return $this->authRequest;
    }

    /**
     * @return AuthMethodFactoryInterface
     */
    public function getAuthMethodFactory(): AuthMethodFactoryInterface
    {
        return $this->authMethodFactory;
    }

    /**
     * @return ResponseModeFactoryInterface
     */
    public function getResponseModeFactory(): ResponseModeFactoryInterface
    {
        return $this->responseModeFactory;
    }

    /**
     * Handle endpoint URI based on auth method
     *
     * @param string $endpointClaim
     *
     * @return string|null
     */
    private function getEndpointUri(string $endpointClaim): ?string
    {
        $authMethod = $this->getMetadata()->get($endpointClaim . '_auth_method') ?: 'client_secret_basic';
        /** @var string|null $endpointUri */
        $endpointUri = $this->getIssuer()->getMetadata()->get($endpointClaim);

        if (! $endpointUri) {
            return null;
        }

        if (! \in_array($authMethod, AuthMethodInterface::TLS_METHODS, true)) {
            return $endpointUri;
        }

        return $this->getIssuer()
            ->getMetadata()
            ->getMtlsEndpointAliases()[$endpointClaim] ?? $endpointUri;
    }

    public function getTokenEndpoint(): string
    {
        $uri = $this->getEndpointUri('token_endpoint');

        if (! $uri) {
            throw new RuntimeException('Unable to retrieve the token endpoint');
        }

        return $uri;
    }

    public function getRevocationEndpoint(): ?string
    {
        return $this->getEndpointUri('revocation_endpoint');
    }

    public function getIntrospectionEndpoint(): ?string
    {
        return $this->getEndpointUri('introspection_endpoint');
    }

    public function getUserinfoEndpoint(): ?string
    {
        return $this->getEndpointUri('userinfo_endpoint');
    }
}
