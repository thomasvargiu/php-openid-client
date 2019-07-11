<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ClaimChecker;

use function hash;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;
use function sprintf;
use function strlen;
use function substr;
use function TMV\OpenIdClient\base64url_encode;

abstract class AbstractHashChecker implements ClaimChecker
{
    /** @var string */
    private $valueToCheck;

    /** @var string */
    private $alg;

    /**
     * SHashChecker constructor.
     *
     * @param string $valueToCheck
     * @param string $alg
     */
    public function __construct(string $valueToCheck, string $alg)
    {
        $this->valueToCheck = $valueToCheck;
        $this->alg = $alg;
    }

    private function getShaSize(string $alg): string
    {
        $size = substr($alg, -3);

        switch ($size) {
            case '512':
                return 'sha512';
            case '384':
                return 'sha384';
            default:
                return 'sha256';
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value): void
    {
        $hash = hash($this->getShaSize($this->alg), $this->valueToCheck, true);
        $generated = base64url_encode(substr($hash, 0, strlen($hash) / 2));

        if ($value !== $generated) {
            throw new InvalidClaimException(sprintf($this->supportedClaim() . ' mismatch, expected %s, got: %s', $generated, $value), $this->supportedClaim(), $value);
        }
    }
}
