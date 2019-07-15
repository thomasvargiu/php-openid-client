<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\Claims;

use function implode;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use function json_encode;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface as HttpClient;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use function TMV\OpenIdClient\base64url_encode;
use TMV\OpenIdClient\Claims\DistributedParser;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Issuer\IssuerFactoryInterface;
use TMV\OpenIdClient\Issuer\IssuerInterface;

class DistributedClaimsTest extends TestCase
{
    public function testUnpackAggregatedClaimsWithNoClaimSources(): void
    {
        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $httpClient = $this->prophesize(HttpClient::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $service = new DistributedParser(
            $httpClient->reveal(),
            $requestFactory->reveal(),
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'age' => 'src1',
            ],
        ];

        $distributed = $service->fetch($client->reveal(), $claims);

        static::assertSame($claims, $distributed);
    }

    public function testUnpackAggregatedClaimsWithNoClaimNames(): void
    {
        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $httpClient = $this->prophesize(HttpClient::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);

        $service = new DistributedParser(
            $httpClient->reveal(),
            $requestFactory->reveal(),
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_sources' => [
                'src1' => [
                    'endpoint' => 'https://endpoint.url/claims',
                    'access_token' => 'access-token',
                ],
            ],
        ];

        $distributed = $service->fetch($client->reveal(), $claims);

        static::assertSame($claims, $distributed);
    }

    public function testUnpackAggregatedClaims(): void
    {
        $jwt = implode('.', [
            base64url_encode((string) json_encode(['alg' => 'none'])),
            base64url_encode((string) json_encode(['age' => 30])),
            '.',
        ]);

        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $httpClient = $this->prophesize(HttpClient::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $requestFactory->createRequest('GET', 'https://endpoint.url/claims')
            ->willReturn($request->reveal());

        $request->withHeader('accept', 'application/jwt')
            ->willReturn($request->reveal());
        $request->withHeader('authorization', 'Bearer ' . 'access-token')
            ->willReturn($request->reveal());

        $response->getStatusCode()->willReturn(201);
        $response->getBody()->willReturn($stream->reveal());
        $stream->__toString()->willReturn($jwt);

        $httpClient->sendRequest($request->reveal())
            ->willReturn($response->reveal());

        $client->getIssuer()->willReturn($issuer->reveal());

        $service = new DistributedParser(
            $httpClient->reveal(),
            $requestFactory->reveal(),
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'age' => 'src1',
            ],
            '_claim_sources' => [
                'src1' => [
                    'endpoint' => 'https://endpoint.url/claims',
                    'access_token' => 'access-token',
                ],
            ],
        ];

        $unpacked = $service->fetch($client->reveal(), $claims);

        static::assertSame(30, $unpacked['age'] ?? null);
        static::assertArrayNotHasKey('_claim_names', $unpacked);
        static::assertArrayNotHasKey('_claim_sources', $unpacked);
    }

    public function testUnpackAggregatedClaimsWithResourceError(): void
    {
        $jwt = implode('.', [
            base64url_encode((string) json_encode(['alg' => 'none'])),
            base64url_encode((string) json_encode(['age' => 30])),
            '.',
        ]);

        $algorithmManager = $this->prophesize(AlgorithmManager::class);
        $JWSVerifier = $this->prophesize(JWSVerifier::class);
        $issuerFactory = $this->prophesize(IssuerFactoryInterface::class);
        $httpClient = $this->prophesize(HttpClient::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $client = $this->prophesize(ClientInterface::class);
        $issuer = $this->prophesize(IssuerInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $stream = $this->prophesize(StreamInterface::class);

        $requestFactory->createRequest('GET', 'https://endpoint.url/claims')
            ->willReturn($request->reveal());

        $request->withHeader('accept', 'application/jwt')
            ->willReturn($request->reveal());
        $request->withHeader('authorization', 'Bearer ' . 'access-token')
            ->willReturn($request->reveal());

        $response->getStatusCode()->willReturn(401);
        $response->getBody()->willReturn($stream->reveal());
        $stream->__toString()->willReturn($jwt);

        $httpClient->sendRequest($request->reveal())
            ->willReturn($response->reveal());

        $client->getIssuer()->willReturn($issuer->reveal());

        $service = new DistributedParser(
            $httpClient->reveal(),
            $requestFactory->reveal(),
            $algorithmManager->reveal(),
            $JWSVerifier->reveal(),
            $issuerFactory->reveal()
        );

        $claims = [
            'sub' => 'foo',
            '_claim_names' => [
                'age' => 'src1',
            ],
            '_claim_sources' => [
                'src1' => [
                    'endpoint' => 'https://endpoint.url/claims',
                    'access_token' => 'access-token',
                ],
            ],
        ];

        $unpacked = $service->fetch($client->reveal(), $claims);

        static::assertSame($claims, $unpacked);
    }
}
