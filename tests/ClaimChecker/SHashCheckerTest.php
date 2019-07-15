<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ClaimChecker;

use Jose\Component\Checker\ClaimChecker;
use TMV\OpenIdClient\ClaimChecker\SHashChecker;

class SHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 's_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new SHashChecker('foo', $alg);
    }
}
