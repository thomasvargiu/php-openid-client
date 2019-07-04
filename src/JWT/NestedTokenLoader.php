<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\JWT;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\NestedToken\NestedTokenLoader as WTNestedTokenLoader;
use Jose\Component\Signature\JWS;
use Throwable;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;

class NestedTokenLoader implements JWTLoader
{
    /** @var WTNestedTokenLoader */
    private $nestedTokenLoader;

    /** @var ClaimCheckerManager */
    private $claimCheckerManager;

    /** @var string[] */
    private $mandatoryClaims;

    public function __construct(
        WTNestedTokenLoader $nestedTokenLoader,
        ?ClaimCheckerManager $claimCheckerManager = null,
        array $mandatoryClaims = []
    ) {
        $this->nestedTokenLoader = $nestedTokenLoader;
        $this->claimCheckerManager = $claimCheckerManager ?: new ClaimCheckerManager([]);
        $this->mandatoryClaims = $mandatoryClaims;
    }

    public function load(string $content, ClientInterface $client): JWS
    {
        try {
            $jws = $this->nestedTokenLoader->load($content, $client->getJWKS(), $client->getIssuer()->getJwks());
        } catch (Throwable $e) {
            throw new RuntimeException('Unable to load nested token', 0, $e);
        }

        if (null === $jws->getPayload()) {
            return $jws;
        }

        $claims = \json_decode($jws->getPayload(), true);

        if (! \is_array($claims)) {
            throw new RuntimeException('Unable to decode claims');
        }

        $this->claimCheckerManager->check($claims, $this->mandatoryClaims);

        return $jws;
    }
}
