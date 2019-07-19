<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Service;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use TMV\OpenIdClient\AuthMethod\AuthMethodFactoryInterface;
use TMV\OpenIdClient\AuthMethod\AuthMethodInterface;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Client\Metadata\ClientMetadataInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use TMV\OpenIdClient\Issuer\Metadata\IssuerMetadataInterface;
use TMV\OpenIdClient\Service\AuthorizationService;
use TMV\OpenIdClient\Token\ResponseTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;
use TMV\OpenIdClient\Token\TokenSetFactoryInterface;
use TMV\OpenIdClient\Token\TokenSetInterface;
use TMV\OpenIdClient\Token\TokenSetVerifierInterface;

class AuthorizationServiceTest extends TestCase
{
    public function testGetAuthorizationUri(): void
    {
        $tokenSetFactory = $this->prophesize(TokenSetFactoryInterface::class);
        $tokenSetVerifier = $this->prophesize(TokenSetVerifierInterface::class);
        $responseTokenVerifier = $this->prophesize(ResponseTokenVerifierInterface::class);
        $tokenDecrypter = $this->prophesize(TokenDecrypterInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $tokenSetFactory->reveal(),
            $tokenSetVerifier->reveal(),
            $responseTokenVerifier->reveal(),
            $tokenDecrypter->reveal(),
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $clientMetadata = $this->prophesize(ClientMetadataInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $uri2 = $this->prophesize(UriInterface::class);

        $openIdClient->getIssuer()->willReturn($issuer->reveal());
        $openIdClient->getMetadata()->willReturn($clientMetadata->reveal());
        $openIdClient->getHttpClient()->willReturn(null);
        $clientMetadata->getClientId()->willReturn('clientId');
        $clientMetadata->getResponseTypes()->willReturn(['code']);
        $clientMetadata->getRedirectUris()->willReturn(['redirect_uri_1']);
        $issuer->getMetadata()->willReturn($issuerMetadata);
        $issuerMetadata->getAuthorizationEndpoint()->willReturn('foo-endpoint');
        $uriFactory->createUri('foo-endpoint')->willReturn($uri->reveal());
        $uri->withQuery('client_id=clientId&scope=openid&response_type=code&redirect_uri=redirect_uri_1')
            ->willReturn($uri2->reveal());
        $uri2->__toString()->willReturn('foo-uri');

        static::assertSame('foo-uri', $service->getAuthorizationUri($openIdClient->reveal()));
    }

    public function testFetchTokenFromCode(): void
    {
        $tokenSetFactory = $this->prophesize(TokenSetFactoryInterface::class);
        $tokenSetVerifier = $this->prophesize(TokenSetVerifierInterface::class);
        $responseTokenVerifier = $this->prophesize(ResponseTokenVerifierInterface::class);
        $tokenDecrypter = $this->prophesize(TokenDecrypterInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $tokenSetFactory->reveal(),
            $tokenSetVerifier->reveal(),
            $responseTokenVerifier->reveal(),
            $tokenDecrypter->reveal(),
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $openIdClient->getHttpClient()->willReturn(null);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $authMethodFactory = $this->prophesize(AuthMethodFactoryInterface::class);
        $authMethod = $this->prophesize(AuthMethodInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $tokenRequest1 = $this->prophesize(RequestInterface::class);
        $tokenRequest2 = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);

        $claims = [
            'grant_type' => 'authorization_code',
            'code' => 'foo-code',
            'redirect_uri' => 'redirect-uri',
        ];

        $requestFactory->createRequest('POST', 'token-endpoint')
            ->willReturn($request->reveal());
        $request->withHeader('content-type', 'application/x-www-form-urlencoded')
            ->willReturn($tokenRequest1->reveal());
        $openIdClient->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata->reveal());
        $issuerMetadata->getTokenEndpoint()->willReturn('token-endpoint');
        $issuerMetadata->get('token_endpoint')->willReturn('token-endpoint');
        $openIdClient->getMetadata()->willReturn($metadata->reveal());
        $openIdClient->getAuthMethodFactory()->willReturn($authMethodFactory->reveal());
        $metadata->getTokenEndpointAuthMethod()->willReturn('auth-method');
        $metadata->get('token_endpoint_auth_method')->willReturn('auth-method');
        $authMethodFactory->create('auth-method')->willReturn($authMethod->reveal());
        $authMethod->createRequest(
            $tokenRequest1->reveal(),
            $openIdClient->reveal(),
            $claims
        )
            ->willReturn($tokenRequest2->reveal());

        $client->sendRequest($tokenRequest2->reveal())
            ->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($stream->reveal());
        $stream->__toString()->willReturn('{"foo":"bar"}');

        $tokenSet = $this->prophesize(TokenSetInterface::class);
        $tokenSetFactory->fromArray(['foo' => 'bar'])->willReturn($tokenSet->reveal());

        static::assertSame($tokenSet->reveal(), $service->grant($openIdClient->reveal(), $claims));
    }
}
