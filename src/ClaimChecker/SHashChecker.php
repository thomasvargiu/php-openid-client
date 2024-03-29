<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ClaimChecker;

final class SHashChecker extends AbstractHashChecker
{
    private const CLAIM_NAME = 's_hash';

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
