<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\JWT\JWTLoader;

class UserinfoService
{
    /** @var null|JWTLoader */
    private $jwtLoader;
    /** @var ClientInterface */
    private $client;
    /** @var RequestFactoryInterface */
    private $requestFactory;

    /**
     * UserinfoService constructor.
     *
     * @param null|JWTLoader $jwtLoader
     * @param null|ClientInterface $client
     * @param null|RequestFactoryInterface $requestFactory
     */
    public function __construct(
        ?JWTLoader $jwtLoader = null,
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null
    ) {
        $this->jwtLoader = $jwtLoader;
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
    }

    public function getUserInfo(OpenIDClient $client, string $accessToken): array
    {
        $endpointUri = $client->getUserinfoEndpoint();

        if (! $endpointUri) {
            throw new InvalidArgumentException('Invalid issuer userinfo endpoint');
        }

        $clientMetadata = $client->getMetadata();

        $request = $this->requestFactory->createRequest('GET', $endpointUri)
            ->withHeader('accept', 'application/json')
            ->withHeader('authorization', 'Bearer ' . $accessToken);

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get userinfo', 0, $e);
        }

        if (200 !== $response->getStatusCode()) {
            throw OAuth2Exception::fromResponse($response);
        }

        $isJwt = $clientMetadata->getUserinfoSignedResponseAlg() || $clientMetadata->getUserinfoEncryptedResponseAlg();

        if ($isJwt && $this->jwtLoader) {
            $payload = $this->jwtLoader->load($response->getBody()->getContents(), $client)->getPayload();
        } elseif ($isJwt) {
            throw new RuntimeException('No JWT loader provided to parse userinfo JWT');
        } else {
            $payload = $response->getBody()->getContents();
        }

        if (! \is_string($payload)) {
            throw new RuntimeException('Unable to parse userinfo claims');
        }

        $claims = \json_decode($payload, true);

        if (! \is_array($claims)) {
            throw new RuntimeException('Unable to parse userinfo claims');
        }

        return $claims;
    }
}
