<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\JWT\JWTLoader;

abstract class AbstractJwt implements ResponseModeInterface
{
    /** @var JWTLoader */
    protected $jwtLoader;

    /** @var ResponseModeInterface */
    protected $baseStrategy;

    /**
     * AbstractJwt constructor.
     *
     * @param JWTLoader $jwtLoader
     * @param ResponseModeInterface $baseStrategy
     */
    public function __construct(JWTLoader $jwtLoader, ResponseModeInterface $baseStrategy)
    {
        $this->jwtLoader = $jwtLoader;
        $this->baseStrategy = $baseStrategy;
    }

    public function getSupportedMode(): string
    {
        return $this->baseStrategy->getSupportedMode() . '.jwt';
    }

    public function parseParams(ServerRequestInterface $request, ClientInterface $client): array
    {
        $baseParams = $this->baseStrategy->parseParams($request, $client);

        /** @var string|null $token */
        $token = $baseParams['response'] ?? null;

        if (! $token) {
            throw new InvalidArgumentException('Invalid authorization request from provider, no "response" parameter');
        }

        $jws = $this->jwtLoader->load($token, $client);

        if (null === $jws->getPayload()) {
            return [];
        }

        $params = \json_decode($jws->getPayload(), true);

        if (! \is_array($params)) {
            throw new RuntimeException('Invalid JWT payload');
        }

        return $params;
    }
}
