<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

abstract class AbstractTLS implements AuthMethodInterface
{
    /** @var StreamFactoryInterface */
    private $streamFactory;

    /**
     * TLS constructor.
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

        $claims = \array_merge($claims, [
            'client_id' => $clientId,
        ]);

        return $request->withBody(
            $this->streamFactory->createStream(\http_build_query($claims))
        );
    }
}
