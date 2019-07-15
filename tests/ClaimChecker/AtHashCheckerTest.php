<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ClaimChecker;

use Jose\Component\Checker\ClaimChecker;
use TMV\OpenIdClient\ClaimChecker\AtHashChecker;

class AtHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 'at_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new AtHashChecker('foo', $alg);
    }
}
