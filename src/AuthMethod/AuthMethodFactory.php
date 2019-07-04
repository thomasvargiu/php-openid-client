<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\AuthMethod;

use TMV\OpenIdClient\Exception\RuntimeException;

class AuthMethodFactory implements AuthMethodFactoryInterface
{
    /** @var AuthMethodInterface[] */
    private $methods = [];

    /**
     * AuthMethodFactory constructor.
     *
     * @param AuthMethodInterface[] $methods
     */
    public function __construct(array $methods = [])
    {
        foreach ($methods as $method) {
            $this->add($method);
        }
    }

    public function add(AuthMethodInterface $authMethod): void
    {
        $this->methods[$authMethod->getSupportedMethod()] = $authMethod;
    }

    /**
     * @return AuthMethodInterface[]
     */
    public function all(): array
    {
        return $this->methods;
    }

    public function create(string $authMethod): AuthMethodInterface
    {
        $method = $this->methods[$authMethod] ?? null;

        if (! $method) {
            throw new RuntimeException('Unsupported auth method "' . $authMethod . '"');
        }

        return $method;
    }
}
