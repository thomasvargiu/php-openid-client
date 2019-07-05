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
use TMV\OpenIdClient\Authorization\AuthRequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\IssuerInterface;
use TMV\OpenIdClient\Model\ClientMetadataInterface;
use TMV\OpenIdClient\Model\IssuerMetadataInterface;
use TMV\OpenIdClient\Service\AuthorizationService;

class AuthorizationServiceTest extends TestCase
{
    public function testGetAuthorizationUri(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $authRequest = $this->prophesize(AuthRequestInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $uri2 = $this->prophesize(UriInterface::class);

        $openIdClient->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata);
        $issuerMetadata->getAuthorizationEndpoint()->willReturn('foo-endpoint');
        $openIdClient->getAuthRequest()->willReturn($authRequest->reveal());
        $authRequest->createParams()->willReturn(['foo' => 'bar']);
        $uriFactory->createUri('foo-endpoint')->willReturn($uri->reveal());
        $uri->withQuery('foo=bar')->willReturn($uri2->reveal());

        $this->assertSame($uri2->reveal(), $service->getAuthorizationUri($openIdClient->reveal()));
    }

    public function testGetAuthorizationUriWithAuthRequest(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $issuerMetadata = $this->prophesize(IssuerMetadataInterface::class);
        $uri = $this->prophesize(UriInterface::class);
        $uri2 = $this->prophesize(UriInterface::class);

        $openIdClient->getIssuer()->willReturn($issuer->reveal());
        $issuer->getMetadata()->willReturn($issuerMetadata);
        $issuerMetadata->getAuthorizationEndpoint()->willReturn('foo-endpoint');
        $openIdClient->getAuthRequest()->shouldNotBeCalled();
        $uriFactory->createUri('foo-endpoint')->willReturn($uri->reveal());
        $uri->withQuery('foo=bar')->willReturn($uri2->reveal());

        $this->assertSame(
            $uri2->reveal(),
            $service->getAuthorizationUri($openIdClient->reveal(), ['foo' => 'bar'])
        );
    }

    public function testFetchTokenFromCode(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $uriFactory = $this->prophesize(UriFactoryInterface::class);

        $service = new AuthorizationService(
            $client->reveal(),
            $requestFactory->reveal(),
            $uriFactory->reveal()
        );

        $openIdClient = $this->prophesize(OpenIDClient::class);
        $metadata = $this->prophesize(ClientMetadataInterface::class);
        $authRequest = $this->prophesize(AuthRequestInterface::class);
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
        $openIdClient->getAuthRequest()->willReturn($authRequest->reveal());
        $openIdClient->getTokenEndpoint()->willReturn('token-endpoint');
        $openIdClient->getAuthMethodFactory()->willReturn($authMethodFactory->reveal());
        $metadata->getTokenEndpointAuthMethod()->willReturn('auth-method');
        $authMethodFactory->create('auth-method')->willReturn($authMethod->reveal());
        $authMethod->createRequest($tokenRequest1->reveal(), $openIdClient->reveal(), $claims)
            ->willReturn($tokenRequest2->reveal());
        $authRequest->getRedirectUri()->willReturn('redirect-uri');

        $client->sendRequest($tokenRequest2->reveal())
            ->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($stream->reveal());
        $stream->__toString()->willReturn('{"foo":"bar"}');

        $this->assertSame(['foo' => 'bar'], $service->fetchTokenFromCode($openIdClient->reveal(), 'foo-code'));
    }
}
