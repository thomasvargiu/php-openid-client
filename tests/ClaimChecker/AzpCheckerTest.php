<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\ClaimChecker;

use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;
use TMV\OpenIdClient\ClaimChecker\AzpChecker;

class AzpCheckerTest extends TestCase
{
    public function testSupportedClaim(): void
    {
        $checker = new AzpChecker('foo');
        static::assertSame('azp', $checker->supportedClaim());
    }

    public function testCheckClaim(): void
    {
        $checker = new AzpChecker('foo');
        $checker->checkClaim('foo');

        static::assertTrue(true);
    }

    public function testCheckClaimFail(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageRegExp('/azp must be the client_id/');

        $checker = new AzpChecker('foo');
        $checker->checkClaim('bar');
    }
}
