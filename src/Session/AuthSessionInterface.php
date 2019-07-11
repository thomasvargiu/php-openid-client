<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Session;

use JsonSerializable;

interface AuthSessionInterface extends JsonSerializable
{
    public function getState(): ?string;

    public function getNonce(): ?string;

    public function setState(?string $state): void;

    public function setNonce(?string $nonce): void;

    public static function fromArray(array $array): self;
}
