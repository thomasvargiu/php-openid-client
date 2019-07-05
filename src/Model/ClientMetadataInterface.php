<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Model;

use JsonSerializable;

interface ClientMetadataInterface extends JsonSerializable
{
    /**
     * @param string $name
     *
     * @return mixed|null
     */
    public function get(string $name);

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool;

    public function getClientId(): string;

    public function getClientSecret(): ?string;

    /**
     * @return string[]
     */
    public function getRedirectUris(): array;

    public function getTokenEndpointAuthMethod(): string;

    public function getAuthorizationSignedResponseAlg(): ?string;

    public function getAuthorizationEncryptedResponseAlg(): ?string;

    public function getAuthorizationEncryptedResponseEnc(): ?string;

    public function getUserinfoSignedResponseAlg(): ?string;

    public function getUserinfoEncryptedResponseAlg(): ?string;

    public function getUserinfoEncryptedResponseEnc(): ?string;

    public function getRequestObjectSigningAlg(): ?string;

    public function getRequestObjectEncryptionAlg(): ?string;

    public function getRequestObjectEncryptionEnc(): ?string;

    public function getIntrospectionEndpointAuthMethod(): string;

    public function getRevocationEndpointAuthMethod(): string;

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array;
}
