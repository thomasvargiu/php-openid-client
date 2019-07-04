<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Model;

class AuthSession implements AuthSessionInterface
{
    private $values = [];

    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->values);
    }

    public function set(string $name, $value): void
    {
        $this->values[$name] = $value;
    }

    /**
     * @param string $name
     *
     * @return null|mixed
     */
    public function get(string $name)
    {
        return $this->values[$name] ?? null;
    }

    public function del(string $name): void
    {
        if ($this->has($name)) {
            unset($this->values[$name]);
        }
    }

    public function all(): array
    {
        return $this->values;
    }

    public function clear(): void
    {
        $this->values = [];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->values;
    }
}
