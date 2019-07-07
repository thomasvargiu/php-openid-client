<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use Psr\Http\Message\RequestInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;

abstract class AbstractTLS implements AuthMethodInterface
{
    public function createRequest(
        RequestInterface $request,
        OpenIDClient $client,
        array $claims
    ): RequestInterface {
        $clientId = $client->getMetadata()->getClientId();

        $claims = \array_merge($claims, [
            'client_id' => $clientId,
        ]);

        $request->getBody()->write(\http_build_query($claims));

        return $request;
    }
}
