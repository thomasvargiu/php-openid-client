<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Token\IdTokenVerifier;
use TMV\OpenIdClient\Token\IdTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypter;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;

class UserinfoService
{
    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var IdTokenVerifierInterface */
    private $idTokenVerifier;

    /** @var TokenDecrypterInterface */
    private $idTokenDecrypter;

    /**
     * UserinfoService constructor.
     *
     * @param null|ClientInterface $client
     * @param IdTokenVerifierInterface|null $idTokenVerifier
     * @param TokenDecrypterInterface|null $idTokenDecrypter
     * @param null|RequestFactoryInterface $requestFactory
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?IdTokenVerifierInterface $idTokenVerifier = null,
        ?TokenDecrypterInterface $idTokenDecrypter = null,
        ?RequestFactoryInterface $requestFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->idTokenVerifier = $idTokenVerifier ?: new IdTokenVerifier();
        $this->idTokenDecrypter = $idTokenDecrypter ?: new TokenDecrypter();
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

        if ($isJwt) {
            $token = $this->idTokenDecrypter->decryptToken($client, (string) $response->getBody(), 'userinfo');
            $payload = $this->idTokenVerifier->validateUserinfoToken($client, $token);
        } else {
            $payload = \json_decode((string) $response->getBody(), true);
        }

        if (! \is_array($payload)) {
            throw new RuntimeException('Unable to parse userinfo claims');
        }

        return $payload;
    }
}
