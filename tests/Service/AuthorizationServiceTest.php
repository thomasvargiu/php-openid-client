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
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\IssuerInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;
use TMV\OpenIdClient\Service\AuthorizationService;
use TMV\OpenIdClient\Token\ResponseTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;
use TMV\OpenIdClient\Token\TokenSetVerifierInterface;

class AuthorizationServiceTest extends TestCase
{
    public function testGetAuthorizationUri(): void
    {
        $tokenSetVerifier = $this->prophesize(TokenSetVerifierInterface::class);
        $responseTokenVerifier = $this->prophesize(ResponseTokenVerifierInterface::class);
        $tokenDecrypter = $this->prophesize(TokenDecrypterInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
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
        $clientMetadata->getClientId()->willReturn('clientId');
        $clientMetadata->getResponseTypes()->willReturn(['response_type_1']);
        $clientMetadata->getRedirectUris()->willReturn(['redirect_uri_1']);
        $issuer->getMetadata()->willReturn($issuerMetadata);
        $issuerMetadata->getAuthorizationEndpoint()->willReturn('foo-endpoint');
        $uriFactory->createUri('foo-endpoint')->willReturn($uri->reveal());
        $uri->withQuery('client_id=clientId&scope=openid&response_type=response_type_1&redirect_uri=redirect_uri_1')
            ->willReturn($uri2->reveal());
        $uri2->__toString()->willReturn('foo-uri');

        $this->assertSame('foo-uri', $service->getAuthorizationUri($openIdClient->reveal()));
    }

    public function testFetchTokenFromCode(): void
    {
        $tokenSetVerifier = $this->prophesize(TokenSetVerifierInterface::class);
        $responseTokenVerifier = $this->prophesize(ResponseTokenVerifierInterface::class);
        $tokenDecrypter = $this->prophesize(TokenDecrypterInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $tokenSetVerifier->reveal(),
            $responseTokenVerifier->reveal(),
            $tokenDecrypter->reveal(),
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $authMethodFactory = $this->prophesize(AuthMethodFactoryInterface::class);
        $authMethod = $this->prophesize(AuthMethodInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $tokenRequest1 = $this->prophesize(RequestInterface::class);
        $tokenRequest2 = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $claims = [
            'grant_type' => 'authorization_code',
            'code' => 'foo-code',
            'redirect_uri' => 'redirect-uri',
        ];

        $requestFactory->createRequest('POST', 'token-endpoint')
            ->willReturn($request->reveal());
        $request->withHeader('content-type', 'application/x-www-form-urlencoded')
            ->willReturn($tokenRequest1->reveal());
        $openIdClient->getMetadata()->willReturn($metadata->reveal());
        $openIdClient->getTokenEndpoint()->willReturn('token-endpoint');
        $openIdClient->getAuthMethodFactory()->willReturn($authMethodFactory->reveal());
        $metadata->getTokenEndpointAuthMethod()->willReturn('auth-method');
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

        $this->assertSame(['foo' => 'bar'], $service->grant($openIdClient->reveal(), $claims));
    }
}
