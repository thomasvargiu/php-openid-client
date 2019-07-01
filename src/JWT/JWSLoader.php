<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\JWT;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader as WTJWSLoader;
use Throwable;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;

class JWSLoader implements JWTLoader
{
    /** @var WTJWSLoader */
    private $jwsLoader;
    /** @var ClaimCheckerManager */
    private $claimCheckerManager;
    /** @var string[] */
    private $mandatoryClaims;

    public function __construct(
        WTJWSLoader $jwsLoader,
        ?ClaimCheckerManager $claimCheckedManager = null,
        array $mandatoryClaims = []
    )
    {
        $this->jwsLoader = $jwsLoader;
        $this->claimCheckerManager = $claimCheckedManager ?: new ClaimCheckerManager([]);
        $this->mandatoryClaims = $mandatoryClaims;
    }

    public function load(string $content, ClientInterface $client): JWS
    {
        try {
            $jws = $this->jwsLoader->loadAndVerifyWithKeySet($content, $client->getIssuer()->getJwks(), $signature);
        } catch (Throwable $e) {
            throw new RuntimeException('Unable to load JWS token', 0, $e);
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
