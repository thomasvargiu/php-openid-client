<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Token;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Issuer\IssuerInterface;
use function TMV\OpenIdClient\jose_secret_key;

abstract class AbstractTokenVerifier
{
    protected function getSigningJWKSet(ClientInterface $client, string $expectedAlg, ?string $kid = null): JWKSet
    {
        $metadata = $client->getMetadata();
        $issuer = $client->getIssuer();

        if (0 !== strpos($expectedAlg, 'HS')) {
            // not symmetric key
            return null !== $kid
                ? new JWKSet([$this->getIssuerJWKFromKid($issuer, $kid)])
                : $issuer->getJwks();
        }

        $clientSecret = $metadata->getClientSecret();

        if (null === $clientSecret) {
            throw new RuntimeException('Unable to verify token without client_secret');
        }

        return new JWKSet([jose_secret_key($clientSecret)]);
    }

    protected function getIssuerJWKFromKid(IssuerInterface $issuer, string $kid): JWK
    {
        $jwks = $issuer->getJwks();

        $jwk = $jwks->selectKey('sig', null, ['kid' => $kid]);

        if (null === $jwk) {
            $issuer->updateJwks();
            $jwk = $issuer->getJwks()->selectKey('sig', null, ['kid' => $kid]);
        }

        if (null === $jwk) {
            throw new RuntimeException('Unable to find the jwk with the provided kid: ' . $kid);
        }

        return $jwk;
    }
}
