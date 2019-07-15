<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

interface TokenSetInterface
{
    public function getTokenType(): ?string;

    public function getAccessToken(): ?string;

    public function getIdToken(): ?string;

    public function getRefreshToken(): ?string;

    public function getExpiresIn(): ?int;

    public function getCodeVerifier(): ?string;

    public function getCode(): ?string;

    public function getState(): ?string;

    public function claims(): array;

    public function withIdToken(string $idToken): self;
}
