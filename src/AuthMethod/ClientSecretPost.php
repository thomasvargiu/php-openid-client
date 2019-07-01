<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

final class ClientSecretPost implements AuthMethodInterface
{
    /** @var StreamFactoryInterface */
    private $streamFactory;

    public function getSupportedMethod(): string
    {
        return 'client_secret_post';
    }

    /**
     * ClientSecretBasic constructor.
     * @param null|StreamFactoryInterface $streamFactory
     */
    public function __construct(?StreamFactoryInterface $streamFactory = null)
    {
        $this->streamFactory = $streamFactory ?: Psr17FactoryDiscovery::findStreamFactory();
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

        $claims = \array_merge($claims, [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);

        return $request->withBody(
            $this->streamFactory->createStream(\http_build_query($claims))
        );
    }
}
