<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Model;

use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Model\ClientMetadata;

class ClientMetadataTest extends TestCase
{
    public function testFromClaims(): void
    {
        $metadata = ClientMetadata::fromClaims([
            'client_id' => 'foo',
            'redirect_uris' => ['bar'],
        ]);

        $this->assertSame('foo', $metadata->getClientId());
        $this->assertSame(['bar'], $metadata->getRedirectUris());
    }

    public function testFromClaimsWithNoClientId(): void
    {
        $this->expectException(InvalidArgumentException::class);

        ClientMetadata::fromClaims([
            'redirect_uris' => ['bar'],
        ]);
    }

    public function testGetClientId(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame('foo', $metadata->getClientId());
    }

    public function testGetUserinfoEncryptedResponseAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getUserinfoEncryptedResponseAlg());

        $metadata = new ClientMetadata('foo', [
            'userinfo_encrypted_response_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getUserinfoEncryptedResponseAlg());
    }

    public function testGetRevocationEndpointAuthMethod(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame($metadata->getTokenEndpointAuthMethod(), $metadata->getRevocationEndpointAuthMethod());

        $metadata = new ClientMetadata('foo', [
            'revocation_endpoint_auth_method' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getRevocationEndpointAuthMethod());
    }

    public function testGetClientSecret(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getClientSecret());

        $metadata = new ClientMetadata('foo', [
            'client_secret' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getClientSecret());
    }

    public function testGetAuthorizationEncryptedResponseAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getAuthorizationEncryptedResponseAlg());

        $metadata = new ClientMetadata('foo', [
            'authorization_encrypted_response_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getAuthorizationEncryptedResponseAlg());
    }

    public function testGetUserinfoSignedResponseAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getUserinfoSignedResponseAlg());

        $metadata = new ClientMetadata('foo', [
            'userinfo_signed_response_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getUserinfoSignedResponseAlg());
    }

    public function testGetIntrospectionEndpointAuthMethod(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame($metadata->getTokenEndpointAuthMethod(), $metadata->getIntrospectionEndpointAuthMethod());

        $metadata = new ClientMetadata('foo', [
            'introspection_endpoint_auth_method' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getIntrospectionEndpointAuthMethod());
    }

    public function testGetUserinfoEncryptedResponseEnc(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getUserinfoEncryptedResponseEnc());

        $metadata = new ClientMetadata('foo', [
            'userinfo_encrypted_response_enc' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getUserinfoEncryptedResponseEnc());
    }

    public function testGetAuthorizationEncryptedResponseEnc(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getAuthorizationEncryptedResponseEnc());

        $metadata = new ClientMetadata('foo', [
            'authorization_encrypted_response_enc' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getAuthorizationEncryptedResponseEnc());
    }

    public function testGetRequestObjectSigningAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getRequestObjectSigningAlg());

        $metadata = new ClientMetadata('foo', [
            'request_object_signing_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getRequestObjectSigningAlg());
    }

    public function testGetRequestObjectEncryptionAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getRequestObjectEncryptionAlg());

        $metadata = new ClientMetadata('foo', [
            'request_object_encryption_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getRequestObjectEncryptionAlg());
    }

    public function testGetRequestObjectEncryptionEnc(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getRequestObjectEncryptionEnc());

        $metadata = new ClientMetadata('foo', [
            'request_object_encryption_enc' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getRequestObjectEncryptionEnc());
    }

    public function testGetAuthorizationSignedResponseAlg(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertNull($metadata->getAuthorizationSignedResponseAlg());

        $metadata = new ClientMetadata('foo', [
            'authorization_signed_response_alg' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getAuthorizationSignedResponseAlg());
    }

    public function testGetTokenEndpointAuthMethod(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame('client_secret_basic', $metadata->getTokenEndpointAuthMethod());

        $metadata = new ClientMetadata('foo', [
            'token_endpoint_auth_method' => 'foo',
        ]);

        $this->assertSame('foo', $metadata->getTokenEndpointAuthMethod());
    }

    public function testDefaults(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertFalse($metadata->get('require_auth_time'));
        $this->assertFalse($metadata->get('tls_client_certificate_bound_access_tokens'));
        $this->assertSame([], $metadata->get('response_types'));
        $this->assertSame([], $metadata->get('post_logout_redirect_uris'));
        $this->assertSame('RS256', $metadata->get('id_token_signed_response_alg'));
        $this->assertSame('client_secret_basic', $metadata->getTokenEndpointAuthMethod());
    }

    public function testGet(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame('foo', $metadata->get('client_id'));
    }

    public function testHas(): void
    {
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertTrue($metadata->has('client_id'));
        $this->assertFalse($metadata->has('foo'));
    }

    public function testJsonSerialize(): void
    {
        $expected = [
            'client_id' => 'foo',
            'redirect_uris' => ['bar'],
        ];
        $metadata = new ClientMetadata('foo', ['redirect_uris' => ['bar']]);

        $this->assertSame($expected, $metadata->jsonSerialize());
    }
}
