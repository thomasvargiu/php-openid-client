<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\ResponseMode;

use Psr\Http\Message\ServerRequestInterface;

final class ResponseModeProvider implements ResponseModeProviderInterface
{
    /** @var ResponseModeFactoryInterface */
    private $responseModeManager;

    /**
     * ResponseModeProvider constructor.
     *
     * @param ResponseModeFactoryInterface $responseModeManager
     */
    public function __construct(ResponseModeFactoryInterface $responseModeManager)
    {
        $this->responseModeManager = $responseModeManager;
    }

    public function getResponseMode(ServerRequestInterface $serverRequest): ResponseModeInterface
    {
        $responseMode = $this->inferResponseMode($serverRequest);

        return $this->responseModeManager->create($responseMode);
    }

    private function inferResponseMode(ServerRequestInterface $serverRequest): string
    {
        $method = \strtoupper($serverRequest->getMethod());

        if ('POST' === $method) {
            $params = $serverRequest->getParsedBody();
            $baseMethod = 'form_post';
        } elseif ($serverRequest->getUri()->getFragment()) {
            \parse_str($serverRequest->getUri()->getFragment(), $params);
            $baseMethod = 'fragment';
        } else {
            $params = $serverRequest->getQueryParams();
            $baseMethod = 'query';
        }

        $isJwt = \array_key_exists('response', $params);

        if (! $isJwt) {
            return $baseMethod;
        }

        return $baseMethod . '.jwt';
    }
}
