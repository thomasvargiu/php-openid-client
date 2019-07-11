<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ClaimChecker;

use Jose\Component\Checker\ClaimChecker;
use TMV\OpenIdClient\ClaimChecker\CHashChecker;

class CHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 'c_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new CHashChecker('foo', $alg);
    }
}
