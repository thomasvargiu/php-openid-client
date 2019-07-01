<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Model;

use TMV\OpenIdClient\Exception\InvalidArgumentException;

class IssuerMetadata implements IssuerMetadataInterface
{
    /**
     * @var array
     */
    private $claims;

    private static $requiredKeys = [
        'issuer',
        'authorization_endpoint',
        'jwks_uri',
    ];

    private static $defaults = [
        'scopes_supported' => ['openid'],
        'response_types_supported' => ['code', 'id_token', 'token id_token'],
        'response_modes_supported' => ['query', 'fragment'],
        'grant_types_supported' => ['authorization_code', 'implicit'],
        'acr_values_supported' => [],
        'subject_types_supported' => ['public'],
        'display_values_supported' => [],
        'claim_types_supported' => ['normal'],
        'claim_supported' => [],

        'claims_parameter_supported' => false,
        'request_parameter_supported' => false,
        'request_uri_parameter_supported' => true,
        'require_request_uri_registration' => false,
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],

        'id_token_signing_alg_values_supported' => ['RS256'],
        'id_token_encryption_alg_values_supported' => [],
        'id_token_encryption_enc_values_supported' => [],

        'userinfo_signing_alg_values_supported' => ['RS256'],
        'userinfo_encryption_alg_values_supported' => [],
        'userinfo_encryption_enc_values_supported' => [],

        'authorization_signing_alg_values_supported' => ['RS256'],
        'authorization_encryption_alg_values_supported' => [],
        'authorization_encryption_enc_values_supported' => [],

        'introspection_endpoint_auth_methods_supported' => ['client_secret_basic'],
        'introspection_endpoint_auth_signing_alg_values_supported' => ['RS256'],

        'introspection_signing_alg_values_supported' => ['RS256'],
        'introspection_encryption_alg_values_supported' => [],
        'introspection_encryption_enc_values_supported' => [],

        'request_object_signing_alg_values_supported' => ['RS256'],
        'request_object_encryption_alg_values_supported' => [],
        'request_object_encryption_enc_values_supported' => [],

        'revocation_endpoint_auth_methods_supported' => [],
        'revocation_signing_alg_values_supported' => ['RS256'],

        'frontchannel_logout_supported' => false,
        'frontchannel_logout_session_supported' => false,
        'backchannel_logout_supported' => false,
        'backchannel_logout_session_supported' => false,
        'tls_client_certificate_bound_access_tokens' => false,
        'mtls_endpoint_aliases' => [],
    ];

    /**
     * IssuerMetadata constructor.
     * @param string $issuer
     * @param string $authorizationEndpoint
     * @param string $jwksUri
     * @param array $claims
     */
    public function __construct(
        string $issuer,
        string $authorizationEndpoint,
        string $jwksUri,
        array $claims = []
    ) {
        $requiredClaims = [
            'issuer' => $issuer,
            'authorization_endpoint' => $authorizationEndpoint,
            'jwks_uri' => $jwksUri,
        ];

        $defaults = static::$defaults;

        $this->claims = \array_merge($defaults, $claims, $requiredClaims);
    }

    public static function fromClaims(array $claims): self
    {
        $missingKeys = \array_diff(static::$requiredKeys, \array_keys($claims));
        if (0 !== count($missingKeys)) {
            throw new InvalidArgumentException('Invalid issuer metadata. Missing keys: ' . \implode(', ', $missingKeys));
        }

        return new self(
            $claims['issuer'],
            $claims['authorization_endpoint'],
            $claims['jwks_uri'],
            $claims
        );
    }

    /**
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->claims['issuer'];
    }
    /**
     * @return string
     */
    public function getAuthorizationEndpoint(): string
    {
        return $this->claims['authorization_endpoint'];
    }
    /**
     * @return string|null
     */
    public function getTokenEndpoint(): ?string
    {
        return $this->claims['token_endpoint'];
    }
    /**
     * @return string|null
     */
    public function getUserinfoEndpoint(): ?string
    {
        return $this->claims['userinfo_endpoint'];
    }
    /**
     * @return string|null
     */
    public function getRegistrationEndpoint(): ?string
    {
        return $this->claims['registration_endpoint'];
    }
    /**
     * @return string
     */
    public function getJwksUri(): string
    {
        return $this->claims['jwks_uri'];
    }
    /**
     * @return string[]
     */
    public function getScopesSupported(): array
    {
        return $this->claims['scopes_supported'];
    }
    /**
     * @return string[]
     */
    public function getResponseTypesSupported(): array
    {
        return $this->claims['response_types_supported'];
    }
    /**
     * @return string[]
     */
    public function getResponseModesSupported(): array
    {
        return $this->claims['response_modes_supported'];
    }
    /**
     * @return string[]
     */
    public function getGrantTypesSupported(): array
    {
        return $this->claims['grant_types_supported'];
    }
    /**
     * @return string[]
     */
    public function getAcrValuesSupported(): array
    {
        return $this->claims['acr_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getSubjectTypesSupported(): array
    {
        return $this->claims['subject_types_supported'];
    }
    /**
     * @return string[]
     */
    public function getDisplayValuesSupported(): array
    {
        return $this->claims['display_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getClaimTypesSupported(): array
    {
        return $this->claims['claim_types_supported'];
    }
    /**
     * @return string[]
     */
    public function getClaimSupported(): array
    {
        return $this->claims['claim_supported'];
    }
    /**
     * @return string|null
     */
    public function getServiceDocumentation(): ?string
    {
        return $this->claims['service_documentation'];
    }
    /**
     * @return string[]|null
     */
    public function getClaimsLocalesSupported(): ?array
    {
        return $this->claims['claims_locales_supported'];
    }
    /**
     * @return string[]|null
     */
    public function getUiLocalesSupported(): ?array
    {
        return $this->claims['ui_locales_supported'];
    }
    /**
     * @return bool
     */
    public function isClaimsParameterSupported(): bool
    {
        return $this->claims['claims_parameter_supported'];
    }
    /**
     * @return bool
     */
    public function isRequestParameterSupported(): bool
    {
        return $this->claims['request_parameter_supported'];
    }
    /**
     * @return bool
     */
    public function isRequestUriParameterSupported(): bool
    {
        return $this->claims['request_uri_parameter_supported'];
    }
    /**
     * @return bool
     */
    public function isRequireRequestUriRegistration(): bool
    {
        return $this->claims['require_request_uri_registration'];
    }
    /**
     * @return string|null
     */
    public function getOpPolicyUri(): ?string
    {
        return $this->claims['op_policy_uri'];
    }
    /**
     * @return string|null
     */
    public function getOpTosUri(): ?string
    {
        return $this->claims['op_tos_uri'];
    }
    /**
     * @return string[]|null
     */
    public function getCodeChallengeMethodsSupported(): ?array
    {
        return $this->claims['code_challenge_methods_supported'];
    }
    /**
     * @return string|null
     */
    public function getSignedMetadata(): ?string
    {
        return $this->claims['signed_metadata'];
    }
    /**
     * @return string[]
     */
    public function getTokenEndpointAuthMethodsSupported(): array
    {
        return $this->claims['token_endpoint_auth_methods_supported'];
    }
    /**
     * @return string[]
     */
    public function getTokenEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->claims['token_endpoint_auth_signing_alg_values_supported'];
    }

    /**
     * @return string[]
     */
    public function getIdTokenSigningAlgValuesSupported(): array
    {
        return $this->claims['id_token_signing_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getIdTokenEncryptionAlgValuesSupported(): array
    {
        return $this->claims['id_token_encryption_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getIdTokenEncryptionEncValuesSupported(): array
    {
        return $this->claims['id_token_encryption_enc_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getUserinfoSigningAlgValuesSupported(): array
    {
        return $this->claims['userinfo_signing_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getUserinfoEncryptionAlgValuesSupported(): array
    {
        return $this->claims['userinfo_encryption_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getUserinfoEncryptionEncValuesSupported(): array
    {
        return $this->claims['userinfo_encryption_enc_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getAuthorizationSigningAlgValuesSupported(): array
    {
        return $this->claims['authorization_signing_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getAuthorizationEncryptionAlgValuesSupported(): array
    {
        return $this->claims['authorization_encryption_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getAuthorizationEncryptionEncValuesSupported(): array
    {
        return $this->claims['authorization_encryption_enc_values_supported'];
    }
    /**
     * @return string|null
     */
    public function getIntrospectionEndpoint(): ?string
    {
        return $this->claims['introspection_endpoint'];
    }
    /**
     * @return string[]
     */
    public function getIntrospectionEndpointAuthMethodsSupported(): array
    {
        return $this->claims['introspection_endpoint_auth_methods_supported'];
    }
    /**
     * @return string[]
     */
    public function getIntrospectionEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->claims['introspection_endpoint_auth_signing_alg_values_supported'];
    }

    /**
     * @return string[]
     */
    public function getIntrospectionSigningAlgValuesSupported(): array
    {
        return $this->claims['introspection_signing_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getIntrospectionEncryptionAlgValuesSupported(): array
    {
        return $this->claims['introspection_encryption_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getIntrospectionEncryptionEncValuesSupported(): array
    {
        return $this->claims['introspection_encryption_enc_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getRequestObjectSigningAlgValuesSupported(): array
    {
        return $this->claims['request_object_signing_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getRequestObjectEncryptionAlgValuesSupported(): array
    {
        return $this->claims['request_object_encryption_alg_values_supported'];
    }
    /**
     * @return string[]
     */
    public function getRequestObjectEncryptionEncValuesSupported(): array
    {
        return $this->claims['request_object_encryption_enc_values_supported'];
    }
    /**
     * @return string|null
     */
    public function getRevocationEndpoint(): ?string
    {
        return $this->claims['revocation_endpoint'];
    }
    /**
     * @return string[]
     */
    public function getRevocationEndpointAuthMethodsSupported(): array
    {
        return $this->claims['revocation_endpoint_auth_methods_supported'];
    }
    /**
     * @return string[]
     */
    public function getRevocationEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->claims['revocation_endpoint_auth_signing_alg_values_supported'];
    }

    /**
     * @return string|null
     */
    public function getCheckSessionIframe(): ?string
    {
        return $this->claims['check_session_iframe'];
    }
    /**
     * @return string|null
     */
    public function getEndSessionIframe(): ?string
    {
        return $this->claims['end_session_iframe'];
    }
    /**
     * @return bool
     */
    public function isFrontchannelLogoutSupported(): bool
    {
        return $this->claims['frontchannel_logout_supported'];
    }
    /**
     * @return bool
     */
    public function isFrontchannelLogoutSessionSupported(): bool
    {
        return $this->claims['frontchannel_logout_session_supported'];
    }
    /**
     * @return bool
     */
    public function isBackchannelLogoutSupported(): bool
    {
        return $this->claims['backchannel_logout_supported'];
    }
    /**
     * @return bool
     */
    public function isBackchannelLogoutSessionSupported(): bool
    {
        return $this->claims['backchannel_logout_session_supported'];
    }
    /**
     * @return bool
     */
    public function isTlsClientCertificateBoundAccessTokens(): bool
    {
        return $this->claims['tls_client_certificate_bound_access_tokens'];
    }
    /**
     * @return array<string, string>
     */
    public function getMtlsEndpointAliases(): array
    {
        return $this->claims['mtls_endpoint_aliases'];
    }

    /**
     * @return array<string, mixed>
     */
    private function getFilteredClaims(): array
    {
        return \array_filter($this->claims, static function ($value, string $key) {
            return \array_key_exists($key, static::$requiredKeys)
                || $value !== static::$defaults[$key] ?? null;
        }, ARRAY_FILTER_USE_BOTH);
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
     * @return bool
     */
    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->claims);
    }

    /**
     * @param string $name
     * @return mixed|null
     */
    public function get(string $name)
    {
        return $this->claims[$name] ?? null;
    }
}
