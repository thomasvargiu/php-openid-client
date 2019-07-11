<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Session;

use function array_filter;

final class AuthSession implements AuthSessionInterface
{
    /** @var null|string */
    private $state;

    /** @var null|string */
    private $nonce;

    public function getState(): ?string
    {
        return $this->state;
    }

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setState(?string $state): void
    {
        $this->state = $state;
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public static function fromArray(array $array): AuthSessionInterface
    {
        $session = new self();
        $session->setState($array['state'] ?? null);
        $session->setNonce($array['nonce'] ?? null);

        return $session;
    }

    public function jsonSerialize(): array
    {
        return array_filter([
            'state' => $this->getState(),
            'nonce' => $this->getNonce(),
        ]);
    }
}
