<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Authorization;

use TMV\OpenIdClient\Authorization\AuthRequest;
use PHPUnit\Framework\TestCase;

class AuthRequestTest extends TestCase
{

    public function testFromParams(): void
    {
        $authRequest = AuthRequest::fromParams([
            'scope' => 'fooscope',
            'client_id' => 'foo',
            'redirect_uri' => 'bar',
        ]);

        $this->assertSame('foo', $authRequest->getClientId());
        $this->assertSame('bar', $authRequest->getRedirectUri());
        $this->assertSame('fooscope', $authRequest->getScope());
    }

    public function testJsonSerialize(): void
    {
        $authRequest = AuthRequest::fromParams([
            'client_id' => 'foo',
            'redirect_uri' => 'bar',
        ]);

        $array = $authRequest->jsonSerialize();

        $this->assertSame('foo', $array['client_id']);
        $this->assertSame('bar', $array['redirect_uri']);
        $this->assertSame('openid', $array['scope']);
        $this->assertSame('code', $array['response_type']);
        $this->assertSame('query', $array['response_mode']);
    }

    public function testCreateParams(): void
    {
        $authRequest = AuthRequest::fromParams([
            'client_id' => 'foo',
            'redirect_uri' => 'bar',
        ]);

        $array = $authRequest->createParams();

        $this->assertSame('foo', $array['client_id']);
        $this->assertSame('bar', $array['redirect_uri']);
        $this->assertSame('openid', $array['scope']);
        $this->assertSame('code', $array['response_type']);
        $this->assertSame('query', $array['response_mode']);
    }

    public function testGetClientId(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertSame('foo', $authRequest->getClientId());
    }

    public function testGetUiLocales(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getUiLocales());

        $authRequest = new AuthRequest('foo', 'bar', ['ui_locales' => 'it_IT']);
        $this->assertSame('it_IT', $authRequest->getUiLocales());
    }

    public function testGetRequest(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getRequest());

        $authRequest = new AuthRequest('foo', 'bar', ['request' => 'foo']);
        $this->assertSame('foo', $authRequest->getRequest());
    }

    public function testWithParams(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $authRequest2 = $authRequest->withParams(['request' => 'foo']);

        $this->assertNotSame($authRequest2, $authRequest);
        $this->assertNull($authRequest->getRequest());
        $this->assertSame('foo', $authRequest2->getRequest());
    }

    public function testGetCodeChallengeMethod(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getCodeChallengeMethod());

        $authRequest = new AuthRequest('foo', 'bar', ['code_challenge_method' => 'foo']);
        $this->assertSame('foo', $authRequest->getCodeChallengeMethod());
    }

    public function testGetState(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getState());

        $authRequest = new AuthRequest('foo', 'bar', ['state' => 'foo']);
        $this->assertSame('foo', $authRequest->getState());
    }

    public function testGetLoginHint(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getLoginHint());

        $authRequest = new AuthRequest('foo', 'bar', ['login_hint' => 'foo']);
        $this->assertSame('foo', $authRequest->getLoginHint());
    }

    public function testGetDisplay(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getDisplay());

        $authRequest = new AuthRequest('foo', 'bar', ['display' => 'foo']);
        $this->assertSame('foo', $authRequest->getDisplay());
    }

    public function testGetMaxAge(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getMaxAge());

        $authRequest = new AuthRequest('foo', 'bar', ['max_age' => 3]);
        $this->assertSame(3, $authRequest->getMaxAge());
    }

    public function testGetRedirectUri(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertSame('bar', $authRequest->getRedirectUri());
    }

    public function testGetNonce(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getNonce());

        $authRequest = new AuthRequest('foo', 'bar', ['nonce' => 'foo']);
        $this->assertSame('foo', $authRequest->getNonce());
    }

    public function testGetCodeChallenge(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getCodeChallenge());

        $authRequest = new AuthRequest('foo', 'bar', ['code_challenge' => 'foo']);
        $this->assertSame('foo', $authRequest->getCodeChallenge());
    }

    public function testGetAcrValues(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getAcrValues());

        $authRequest = new AuthRequest('foo', 'bar', ['acr_values' => 'foo']);
        $this->assertSame('foo', $authRequest->getAcrValues());
    }

    public function testGetScope(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertSame('openid', $authRequest->getScope());

        $authRequest = new AuthRequest('foo', 'bar', ['scope' => 'foo']);
        $this->assertSame('foo', $authRequest->getScope());
    }

    public function testGetResponseMode(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertSame('query', $authRequest->getResponseMode());

        $authRequest = new AuthRequest('foo', 'bar', ['response_mode' => 'foo']);
        $this->assertSame('foo', $authRequest->getResponseMode());
    }

    public function testGetPrompt(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getPrompt());

        $authRequest = new AuthRequest('foo', 'bar', ['prompt' => 'foo']);
        $this->assertSame('foo', $authRequest->getPrompt());
    }

    public function testGetIdTokenHint(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertNull($authRequest->getIdTokenHint());

        $authRequest = new AuthRequest('foo', 'bar', ['id_token_hint' => 'foo']);
        $this->assertSame('foo', $authRequest->getIdTokenHint());
    }

    public function testGetResponseType(): void
    {
        $authRequest = new AuthRequest('foo', 'bar');

        $this->assertSame('code', $authRequest->getResponseType());

        $authRequest = new AuthRequest('foo', 'bar', ['response_type' => 'foo']);
        $this->assertSame('foo', $authRequest->getResponseType());
    }
}
