<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Token;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Token\TokenSet;

class TokenSetTest extends TestCase
{
    public function testGetTokenType(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getTokenType());

        $authResponse = TokenSet::fromParams(['token_type' => 'foo']);
        $this->assertSame('foo', $authResponse->getTokenType());
    }

    public function testGetCode(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getCode());

        $authResponse = TokenSet::fromParams(['code' => 'foo']);
        $this->assertSame('foo', $authResponse->getCode());
    }

    public function testGetExpiresIn(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getExpiresIn());

        $authResponse = TokenSet::fromParams(['expires_in' => '3']);
        $this->assertSame(3, $authResponse->getExpiresIn());
    }

    public function testGetIdToken(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getIdToken());

        $authResponse = TokenSet::fromParams(['id_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getIdToken());
    }

    public function testGetRefreshToken(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getRefreshToken());

        $authResponse = TokenSet::fromParams(['refresh_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getRefreshToken());
    }

    public function testGetCodeVerifier(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getCodeVerifier());

        $authResponse = TokenSet::fromParams(['code_verifier' => 'foo']);
        $this->assertSame('foo', $authResponse->getCodeVerifier());
    }

    public function testGetState(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getState());

        $authResponse = TokenSet::fromParams(['state' => 'foo']);
        $this->assertSame('foo', $authResponse->getState());
    }

    public function testGetAccessToken(): void
    {
        $authResponse = new TokenSet();
        $this->assertNull($authResponse->getAccessToken());

        $authResponse = TokenSet::fromParams(['access_token' => 'foo']);
        $this->assertSame('foo', $authResponse->getAccessToken());
    }
}
