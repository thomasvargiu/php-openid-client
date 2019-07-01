<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

class TokenResponse implements TokenResponseInterface
{
    /** @var string|null */
    private $tokenType;

    /** @var string|null */
    private $accessToken;

    /** @var string|null */
    private $idToken;

    /** @var string|null */
    private $refreshToken;

    /** @var int|null */
    private $expiresIn;

    /** @var string|null */
    private $codeVerifier;

    public static function fromParams(array $data): TokenResponseInterface
    {
        $token = new static();
        $token->tokenType = $data['token_type'] ?? null;
        $token->accessToken = $data['access_token'] ?? null;
        $token->idToken = $data['id_token'] ?? null;
        $token->refreshToken = $data['refresh_token'] ?? null;
        $token->expiresIn = \array_key_exists('expires_in', $data) ? (int) $data['expires_in'] : null;
        $token->codeVerifier = $data['code_verifier'] ?? null;

        return $token;
    }

    public function withTokenType(?string $tokenType): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->tokenType = $tokenType;

        return $clone;
    }

    public function withAccessToken(?string $accessToken): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->accessToken = $accessToken;

        return $clone;
    }

    public function withIdToken(?string $idToken): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->idToken = $idToken;

        return $clone;
    }

    public function withRefreshToken(?string $refreshToken): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->refreshToken = $refreshToken;

        return $clone;
    }

    public function withExpiresIn(?int $expiresIn): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->expiresIn = $expiresIn;

        return $clone;
    }

    public function withCodeVerifier(?string $codeVerifier): TokenResponseInterface
    {
        $clone = clone $this;
        $clone->codeVerifier = $codeVerifier;

        return $clone;
    }

    /**
     * @return string|null
     */
    public function getTokenType(): ?string
    {
        return $this->tokenType;
    }

    /**
     * @return string|null
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    /**
     * @return string|null
     */
    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * @return string|null
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    /**
     * @return int|null
     */
    public function getExpiresIn(): ?int
    {
        return $this->expiresIn;
    }

    /**
     * @return string|null
     */
    public function getCodeVerifier(): ?string
    {
        return $this->codeVerifier;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'token_type' => $this->tokenType,
            'access_token' => $this->accessToken,
            'id_token' => $this->idToken,
            'refresh_token' => $this->refreshToken,
            'expires_in' => $this->expiresIn,
            'code_verifier' => $this->codeVerifier,
        ];

        return \array_filter($data, static function ($value) {
            return null !== $value;
        });
    }
}
