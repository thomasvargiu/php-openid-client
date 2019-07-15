<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Claims;

use function array_diff_key;
use function array_flip;
use function array_key_exists;
use function count;
use function explode;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use function json_decode;
use function sprintf;
use function TMV\OpenIdClient\base64url_decode;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Issuer\IssuerFactory;
use TMV\OpenIdClient\Issuer\IssuerFactoryInterface;

abstract class AbstractClaims
{
    /** @var AlgorithmManager */
    protected $algorithmManager;

    /** @var JWSVerifier */
    protected $JWSVerifier;

    /** @var IssuerFactoryInterface */
    protected $issuerFactory;

    /** @var JWSSerializer */
    protected $serializer;

    public function __construct(
        ?AlgorithmManager $algorithmManager = null,
        ?JWSVerifier $JWSVerifier = null,
        ?IssuerFactoryInterface $issuerFactory = null,
        ?JWSSerializer $serializer = null
    ) {
        $this->algorithmManager = $algorithmManager ?: new AlgorithmManager([new RS256()]);
        $this->JWSVerifier = $JWSVerifier ?: new JWSVerifier($this->algorithmManager);
        $this->issuerFactory = $issuerFactory ?: new IssuerFactory();
        $this->serializer = $serializer ?: new CompactSerializer();
    }

    protected function claimJWT(OpenIDClient $client, string $jwt): array
    {
        $issuer = $client->getIssuer();

        $header = json_decode(base64url_decode(explode('.', $jwt)[0] ?? '{}'), true);
        $payload = json_decode(base64url_decode(explode('.', $jwt)[1] ?? '{}'), true);

        /** @var null|string $alg */
        $alg = $header['alg'] ?? null;
        /** @var null|string $kid */
        $kid = $header['kid'] ?? null;

        if (null === $alg) {
            throw new InvalidArgumentException('Claim source is missing JWT header alg property');
        }

        if ('none' === $alg) {
            return $payload;
        }

        /** @var null|string $iss */
        $iss = $payload['iss'] ?? null;

        if (null === $iss || $iss === $issuer->getMetadata()->getIssuer()) {
            $jwks = $issuer->getJwks();
        } else {
            $discovered = $this->issuerFactory->fromUri($iss);
            $jwks = $discovered->getJwks();
        }

        $jws = $this->serializer->unserialize($jwt);

        $jwk = $jwks->selectKey('sig', $this->algorithmManager->get($alg), null !== $kid ? ['kid' => $kid] : []);

        if (null === $jwk) {
            throw new RuntimeException('Unable to get a key to verify claim source JWT');
        }

        if (false === $this->JWSVerifier->verifyWithKey($jws, $jwk, 0)) {
            throw new InvalidArgumentException('Invalid claim source JWT signature');
        }

        return $payload;
    }

    protected function assignClaims(array $claims, array $sourceNames, array $sources): array
    {
        foreach ($sourceNames as $claim => $inSource) {
            if (! array_key_exists($inSource, $sources)) {
                continue;
            }

            if (! $sources[$inSource][$claim]) {
                throw new RuntimeException(sprintf('Unable to find claim "%s" in source "%s"', $claim, $inSource));
            }

            $claims[$claim] = $sources[$inSource][$claim];
            $claims['_claim_names'] = array_diff_key($claims['_claim_names'] ?? [], array_flip([$claim]));
        }

        return $claims;
    }

    protected function cleanClaims(array $claims): array
    {
        if (array_key_exists('_claim_names', $claims) && 0 === count($claims['_claim_names'] ?? [])) {
            $claims = array_diff_key($claims, array_flip(['_claim_names']));
        }

        if (array_key_exists('_claim_sources', $claims) && 0 === count($claims['_claim_sources'] ?? [])) {
            $claims = array_diff_key($claims, array_flip(['_claim_sources']));
        }

        return $claims;
    }
}
