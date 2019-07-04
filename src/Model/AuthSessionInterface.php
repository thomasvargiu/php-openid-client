<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Model;

use JsonSerializable;

interface AuthSessionInterface extends JsonSerializable
{
    public function has(string $name): bool;

    public function set(string $name, $value): void;

    /**
     * @param string $name
     *
     * @return null|mixed
     */
    public function get(string $name);

    public function del(string $name): void;

    public function all(): array;

    public function clear(): void;

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array;
}
