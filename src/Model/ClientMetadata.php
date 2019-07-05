<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Model;

use TMV\OpenIdClient\Exception\InvalidArgumentException;

class ClientMetadata implements ClientMetadataInterface
{
    /**
     * @var array
     */
    private $claims;

    private static $requiredKeys = [
        'client_id',
    ];

    private static $defaults = [
        'client_id' => null,
        'redirect_uris' => [],
        'client_secret' => null,
        'jwks' => null,
        'jwks_uri' => null,
        'id_token_signed_response_alg' => 'RS256',
        'id_token_encrypted_response_alg' => null,
        'id_token_encrypted_response_enc' => null,
        'userinfo_signed_response_alg' => null,
        'userinfo_encrypted_response_alg' => null,
        'userinfo_encrypted_response_enc' => null,
        'response_types' => [],
        'post_logout_redirect_uris' => [],
        'require_auth_time' => false,
        'request_object_signing_alg' => null,
        'request_object_encryption_alg' => null,
        'request_object_encryption_enc' => null,
        'token_endpoint_auth_method' => 'client_secret_basic',
        //'introspection_endpoint_auth_method' => 'client_secret_basic',
        //'revocation_endpoint_auth_method' => 'client_secret_basic',
        'token_endpoint_auth_signing_alg' => null,
        'introspection_endpoint_auth_signing_alg' => null,
        'revocation_endpoint_auth_signing_alg' => null,
        'tls_client_certificate_bound_access_tokens' => false,
    ];

    /**
     * IssuerMetadata constructor.
     *
     * @param string $clientId
     * @param array<string, mixed> $claims
     */
    public function __construct(string $clientId, $claims = [])
    {
        $requiredClaims = [
            'client_id' => $clientId,
        ];

        $defaults = static::$defaults;

        $this->claims = \array_merge($defaults, $claims, $requiredClaims);
    }

    public static function fromClaims(array $claims): self
    {
        $missingKeys = \array_diff(static::$requiredKeys, \array_keys($claims));
        if (0 !== \count($missingKeys)) {
            throw new InvalidArgumentException('Invalid client metadata. Missing keys: ' . \implode(', ', $missingKeys));
        }

        return new self($claims['client_id'], $claims);
    }

    public function getClientId(): string
    {
        return $this->claims['client_id'];
    }

    public function getClientSecret(): ?string
    {
        return $this->claims['client_secret'] ?? null;
    }

    public function getRedirectUris(): array
    {
        return $this->claims['redirect_uris'] ?? [];
    }

    public function getTokenEndpointAuthMethod(): string
    {
        return $this->claims['token_endpoint_auth_method'];
    }

    public function getAuthorizationSignedResponseAlg(): ?string
    {
        return $this->claims['authorization_signed_response_alg'] ?? null;
    }

    public function getAuthorizationEncryptedResponseAlg(): ?string
    {
        return $this->claims['authorization_encrypted_response_alg'] ?? null;
    }

    public function getAuthorizationEncryptedResponseEnc(): ?string
    {
        return $this->claims['authorization_encrypted_response_enc'] ?? null;
    }

    public function getUserinfoSignedResponseAlg(): ?string
    {
        return $this->claims['userinfo_signed_response_alg'] ?? null;
    }

    public function getUserinfoEncryptedResponseAlg(): ?string
    {
        return $this->claims['userinfo_encrypted_response_alg'] ?? null;
    }

    public function getUserinfoEncryptedResponseEnc(): ?string
    {
        return $this->claims['userinfo_encrypted_response_enc'] ?? null;
    }

    public function getRequestObjectSigningAlg(): ?string
    {
        return $this->claims['request_object_signing_alg'] ?? null;
    }

    public function getRequestObjectEncryptionAlg(): ?string
    {
        return $this->claims['request_object_encryption_alg'] ?? null;
    }

    public function getRequestObjectEncryptionEnc(): ?string
    {
        return $this->claims['request_object_encryption_enc'] ?? null;
    }

    public function getIntrospectionEndpointAuthMethod(): string
    {
        return $this->claims['introspection_endpoint_auth_method'] ?? $this->getTokenEndpointAuthMethod();
    }

    public function getRevocationEndpointAuthMethod(): string
    {
        return $this->claims['revocation_endpoint_auth_method'] ?? $this->getTokenEndpointAuthMethod();
    }

    /**
     * @return array<string, mixed>
     */
    private function getFilteredClaims(): array
    {
        return \array_filter($this->claims, static function ($value, string $key) {
            return \array_key_exists($key, static::$requiredKeys)
                || $value !== (static::$defaults[$key] ?? null);
        }, \ARRAY_FILTER_USE_BOTH);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->getFilteredClaims();
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->claims);
    }

    /**
     * @param string $name
     *
     * @return mixed|null
     */
    public function get(string $name)
    {
        return $this->claims[$name] ?? null;
    }
}
