<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\IssuerInterface;
use function TMV\OpenIdClient\checkServerResponse;
use function TMV\OpenIdClient\parseMetadataResponse;

class ClientRegistration
{
    /** @var ClientInterface */
    private $client;
    /** @var RequestFactoryInterface */
    private $requestFactory;
    /** @var StreamFactoryInterface */
    private $streamFactory;

    /** @var string[] */
    private static $registrationClaims = [
        'registration_access_token',
        'registration_client_uri',
        'client_secret_expires_at',
        'client_id_issued_at',
    ];

    /**
     * ClientRegistration constructor.
     * @param null|ClientInterface $client
     * @param null|RequestFactoryInterface $requestFactory
     * @param null|StreamFactoryInterface $streamFactory
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->streamFactory = $streamFactory ?: Psr17FactoryDiscovery::findStreamFactory();
    }

    public function register(
        IssuerInterface $issuer,
        array $claims,
        ?string $initialToken = null
    ): array
    {
        $registrationEndpoint = $issuer->getMetadata()->getRegistrationEndpoint();

        if (! $registrationEndpoint) {
            throw new InvalidArgumentException('Issuer does not support dynamic client registration');
        }

        $encodedMetadata = \json_encode($claims);

        if (false === $encodedMetadata) {
            throw new RuntimeException('Unable to encode client metadata');
        }

        $request = $this->requestFactory->createRequest('POST', $registrationEndpoint)
            ->withHeader('content-type', 'application/json')
            ->withHeader('accept', 'application/json')
            ->withBody($this->streamFactory->createStream($encodedMetadata));

        if ($initialToken) {
            $request = $request->withHeader('authorization', 'Bearer ' . $initialToken);
        }

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to register OpenID client', 0, $e);
        }

        $data = parseMetadataResponse($response, 201);

        if (! \array_key_exists('client_id', $data)) {
            throw new RuntimeException('Registration response did not return a client_id field');
        }

        return $data;
    }

    public function read(string $clientUri, string $accessToken): array
    {
        $request = $this->requestFactory->createRequest('GET', $clientUri)
            ->withHeader('accept', 'application/json')
            ->withHeader('authorization', 'Bearer ' . $accessToken);

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to read OpenID client', 0, $e);
        }

        $claims = parseMetadataResponse($response, 200);

        if (! \array_key_exists('client_id', $claims)) {
            throw new RuntimeException('Registration response did not return a client_id field');
        }

        return $claims;
    }

    public function update(
        string $clientUri,
        string $accessToken,
        array $claims
    ): array
    {
        /** @var array<string, mixed> $clientRegistrationMetadata */
        $clientRegistrationMetadata = \array_intersect_key($claims, \array_flip(static::$registrationClaims));
        /** @var array<string, mixed> $claims */
        $claims = \array_diff_key($claims, $clientRegistrationMetadata);

        $encodedMetadata = \json_encode($claims);

        if (false === $encodedMetadata) {
            throw new RuntimeException('Unable to encode client metadata');
        }

        $request = $this->requestFactory->createRequest('PUT', $clientUri)
            ->withHeader('accept', 'application/json')
            ->withHeader('content-type', 'application/json')
            ->withHeader('authorization', 'Bearer ' . $accessToken)
            ->withBody($this->streamFactory->createStream($encodedMetadata));

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to update OpenID client', 0, $e);
        }

        $data = parseMetadataResponse($response, 200);

        if (! \array_key_exists('client_id', $data)) {
            throw new RuntimeException('Registration response did not return a client_id field');
        }

        /** @var array<string, mixed> $merged */
        $merged = \array_merge($clientRegistrationMetadata, $data);

        return $merged;
    }

    public function delete(string $clientUri, string $accessToken): void
    {
        $request = $this->requestFactory->createRequest('DELETE', $clientUri)
            ->withHeader('authorization', 'Bearer ' . $accessToken);

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to delete OpenID client', 0, $e);
        }

        checkServerResponse($response, 204);
    }
}
