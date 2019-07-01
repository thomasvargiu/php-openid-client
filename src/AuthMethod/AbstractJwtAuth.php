<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;

abstract class AbstractJwtAuth implements AuthMethodInterface
{
    /** @var StreamFactoryInterface */
    protected $streamFactory;

    /**
     * AbstractPrivateKeyJwt constructor.
     * @param null|StreamFactoryInterface $streamFactory
     */
    public function __construct(?StreamFactoryInterface $streamFactory = null)
    {
        $this->streamFactory = $streamFactory ?: Psr17FactoryDiscovery::findStreamFactory();
    }

    abstract protected function createAuthJwt(OpenIDClient $client, array $claims = []): string;

    public function createRequest(
        RequestInterface $request,
        OpenIDClient $client,
        array $claims
    ): RequestInterface {
        $clientId = $client->getMetadata()->getClientId();

        $claims = [
            'client_id' => $clientId,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->createAuthJwt($client, $claims),
        ];

        return $request->withBody(
            $this->streamFactory->createStream(\http_build_query($claims))
        );
    }
}
