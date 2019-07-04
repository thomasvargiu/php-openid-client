<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

interface TokenResponseInterface extends \JsonSerializable
{
    public function getTokenType(): ?string;

    public function getAccessToken(): ?string;

    public function getIdToken(): ?string;

    public function getRefreshToken(): ?string;

    public function getExpiresIn(): ?int;

    public function getCodeVerifier(): ?string;

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array;
}
