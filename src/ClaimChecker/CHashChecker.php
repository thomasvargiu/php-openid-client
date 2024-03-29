<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ClaimChecker;

final class CHashChecker extends AbstractHashChecker
{
    private const CLAIM_NAME = 'c_hash';

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
