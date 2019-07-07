<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Psr\Http\Message\RequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;

final class ClientSecretPost implements AuthMethodInterface
{
    public function getSupportedMethod(): string
    {
        return 'client_secret_post';
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

        $request->getBody()->write(\http_build_query($claims));

        return $request;
    }
}
