<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Authorization;

use TMV\OpenIdClient\Authorization\AuthResponse;
use PHPUnit\Framework\TestCase;

class AuthResponseTest extends TestCase
{

    public function testGetTokenType(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getTokenType());

        $authResponse = AuthResponse::fromParams(['token_type' => 'foo']);
        $this->assertSame('foo', $authResponse->getTokenType());
    }

    public function testGetCode(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getCode());

        $authResponse = AuthResponse::fromParams(['code' => 'foo']);
        $this->assertSame('foo', $authResponse->getCode());
    }

    public function testGetExpiresIn(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getExpiresIn());

        $authResponse = AuthResponse::fromParams(['expires_in' => '3']);
        $this->assertSame(3, $authResponse->getExpiresIn());
    }

    public function testGetIdToken(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getIdToken());

        $authResponse = AuthResponse::fromParams(['id_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getIdToken());
    }

    public function testGetRefreshToken(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getRefreshToken());

        $authResponse = AuthResponse::fromParams(['refresh_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getRefreshToken());
    }

    public function testGetCodeVerifier(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getCodeVerifier());

        $authResponse = AuthResponse::fromParams(['code_verifier' => 'foo']);
        $this->assertSame('foo', $authResponse->getCodeVerifier());
    }

    public function testJsonSerialize(): void
    {
        $authResponse = AuthResponse::fromParams(['state' => 'foo']);
        $this->assertSame(['state' => 'foo'], $authResponse->jsonSerialize());

        $provided = [
            'code' => 'foo-code',
            'state' => 'foo-state',
            'token_type' => 'foo-token_type',
            'access_token' => 'foo-access_token',
            'id_token' => 'foo-id_token',
            'refresh_token' => 'foo-refresh_token',
            'expires_in' => '3',
            'code_verifier' => 'foo-code_verifier',
        ];

        $expected = [
            'code' => 'foo-code',
            'state' => 'foo-state',
            'token_type' => 'foo-token_type',
            'access_token' => 'foo-access_token',
            'id_token' => 'foo-id_token',
            'refresh_token' => 'foo-refresh_token',
            'expires_in' => 3,
            'code_verifier' => 'foo-code_verifier',
        ];

        $authResponse = AuthResponse::fromParams($provided);
        $this->assertSame($expected, $authResponse->jsonSerialize());
    }

    public function testGetState(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getState());

        $authResponse = AuthResponse::fromParams(['state' => 'foo']);
        $this->assertSame('foo', $authResponse->getState());
    }

    public function testGetAccessToken(): void
    {
        $authResponse = new AuthResponse();
        $this->assertNull($authResponse->getAccessToken());

        $authResponse = AuthResponse::fromParams(['access_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getAccessToken());
    }
}
