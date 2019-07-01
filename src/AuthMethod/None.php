<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;

final class None implements AuthMethodInterface
{
    /** @var StreamFactoryInterface */
    private $streamFactory;

    public function getSupportedMethod(): string
    {
        return 'none';
    }

    /**
     * None constructor.
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
        return $request->withBody(
            $this->streamFactory->createStream(\http_build_query($claims))
        );
    }
}
