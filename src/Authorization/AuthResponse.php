<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

class AuthResponse implements AuthResponseInterface
{
    /** @var null|string */
    private $code;

    /** @var null|string */
    private $state;

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

    public static function fromParams(array $data): AuthResponseInterface
    {
        $token = new static();
        $token->code = $data['code'] ?? null;
        $token->state = $data['state'] ?? null;
        $token->tokenType = $data['token_type'] ?? null;
        $token->accessToken = $data['access_token'] ?? null;
        $token->idToken = $data['id_token'] ?? null;
        $token->refreshToken = $data['refresh_token'] ?? null;
        $token->expiresIn = \array_key_exists('expires_in', $data) ? (int) $data['expires_in'] : null;
        $token->codeVerifier = $data['code_verifier'] ?? null;

        return $token;
    }

    /**
     * @return string|null
     */
    public function getCode(): ?string
    {
        return $this->code;
    }

    /**
     * @return string|null
     */
    public function getState(): ?string
    {
        return $this->state;
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
            'code' => $this->code,
            'state' => $this->state,
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
