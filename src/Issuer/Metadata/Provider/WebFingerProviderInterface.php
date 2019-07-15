<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Issuer\Metadata\Provider;

interface WebFingerProviderInterface
{
    public function fetch(string $resource): array;
}
