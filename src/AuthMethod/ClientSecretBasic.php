<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

final class ClientSecretBasic implements AuthMethodInterface
{
    /** @var StreamFactoryInterface */
    private $streamFactory;

    /**
     * ClientSecretBasic constructor.
     *
     * @param null|StreamFactoryInterface $streamFactory
     */
    public function __construct(StreamFactoryInterface $streamFactory = null)
    {
        $this->streamFactory = $streamFactory ?: Psr17FactoryDiscovery::findStreamFactory();
    }

    public function getSupportedMethod(): string
    {
        return 'client_secret_basic';
    }

    public function createRequest(
        RequestInterface $request,
        OpenIDClient $client,
        array $claims
    ): RequestInterface {
        $clientId = $client->getMetadata()->getClientId();
        $clientSecret = $client->getMetadata()->getClientSecret();

        if (! $clientSecret) {
            throw new InvalidArgumentException($this->getSupportedMethod() . ' cannot be used without client_secret metadata');
        }

        return $request->withHeader(
            'Authentication',
            'Basic ' . \base64_encode($clientId . ':' . $clientSecret)
        )->withBody(
            $this->streamFactory->createStream(\http_build_query($claims))
        );
    }
}
