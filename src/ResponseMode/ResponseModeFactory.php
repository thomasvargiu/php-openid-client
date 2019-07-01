<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use TMV\OpenIdClient\Exception\InvalidArgumentException;

final class ResponseModeFactory implements ResponseModeFactoryInterface
{
    /** @var ResponseModeInterface[] */
    private $modes;

    /**
     * @param ResponseModeInterface[] $responseModes
     */
    public function __construct(array $responseModes = [])
    {
        $this->modes = [];
        foreach ($responseModes as $handler) {
            $this->add($handler);
        }
    }

    public function add(ResponseModeInterface $handler): void
    {
        $this->modes[$handler->getSupportedMode()] = $handler;
    }

    /**
     * @return ResponseModeInterface[]
     */
    public function all(): array
    {
        return $this->modes;
    }

    public function create(string $responseMode): ResponseModeInterface
    {
        if (! \array_key_exists($responseMode, $this->modes)) {
            throw new InvalidArgumentException('Unsupported response mode "' . $responseMode . '"');
        }

        return $this->modes[$responseMode];
    }
}
