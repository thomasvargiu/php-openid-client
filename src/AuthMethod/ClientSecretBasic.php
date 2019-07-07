<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Psr\Http\Message\RequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

final class ClientSecretBasic implements AuthMethodInterface
{
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

        $request = $request->withHeader(
            'Authorization',
            'Basic ' . \base64_encode($clientId . ':' . $clientSecret)
        );

        $request->getBody()->write(\http_build_query($claims));

        return $request;
    }
}
