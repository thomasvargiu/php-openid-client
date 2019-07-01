<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Authorization;

interface AuthResponseInterface extends TokenResponseInterface
{
    public function getCode(): ?string;
    public function getState(): ?string;
}
