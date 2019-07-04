<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Authorization;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Authorization\TokenResponse;

class TokenResponseTest extends TestCase
{
    public function testGetTokenType(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getTokenType());

        $tokenResponse = TokenResponse::fromParams(['token_type' => 'foo']);
        $this->assertSame('foo', $tokenResponse->getTokenType());
    }

    public function testGetExpiresIn(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getExpiresIn());

        $tokenResponse = TokenResponse::fromParams(['expires_in' => '3']);
        $this->assertSame(3, $tokenResponse->getExpiresIn());
    }

    public function testGetIdToken(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getIdToken());

        $tokenResponse = TokenResponse::fromParams(['id_token' => 'foo']);
        $this->assertSame('foo', $tokenResponse->getIdToken());
    }

    public function testGetRefreshToken(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getRefreshToken());

        $tokenResponse = TokenResponse::fromParams(['refresh_token' => 'foo']);
        $this->assertSame('foo', $tokenResponse->getRefreshToken());
    }

    public function testGetCodeVerifier(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getCodeVerifier());

        $tokenResponse = TokenResponse::fromParams(['code_verifier' => 'foo']);
        $this->assertSame('foo', $tokenResponse->getCodeVerifier());
    }

    public function testJsonSerialize(): void
    {
        $tokenResponse = TokenResponse::fromParams([]);
        $this->assertSame([], $tokenResponse->jsonSerialize());

        $provided = [
            'token_type' => 'foo-token_type',
            'access_token' => 'foo-access_token',
            'id_token' => 'foo-id_token',
            'refresh_token' => 'foo-refresh_token',
            'expires_in' => '3',
            'code_verifier' => 'foo-code_verifier',
        ];

        $expected = [
            'token_type' => 'foo-token_type',
            'access_token' => 'foo-access_token',
            'id_token' => 'foo-id_token',
            'refresh_token' => 'foo-refresh_token',
            'expires_in' => 3,
            'code_verifier' => 'foo-code_verifier',
        ];

        $tokenResponse = TokenResponse::fromParams($provided);
        $this->assertSame($expected, $tokenResponse->jsonSerialize());
    }

    public function testGetAccessToken(): void
    {
        $tokenResponse = new TokenResponse();
        $this->assertNull($tokenResponse->getAccessToken());

        $tokenResponse = TokenResponse::fromParams(['access_token' => 'foo']);
        $this->assertSame('foo', $tokenResponse->getAccessToken());
    }
}
