<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Authorization\AuthResponseInterface;
use TMV\OpenIdClient\Exception\InvalidStateException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Model\AuthSessionInterface;

class StateCheckerMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authResponse = $request->getAttribute(AuthResponseInterface::class);

        if (! $authResponse instanceof AuthResponseInterface) {
            throw new RuntimeException('Unable to find a valid attribute for ' . AuthResponseInterface::class);
        }

        $authSession = $request->getAttribute(AuthSessionInterface::class);

        if (! $authSession instanceof AuthSessionInterface) {
            throw new RuntimeException('Unable to find a valid attribute for ' . AuthSessionInterface::class);
        }

        if ($authSession->get('state') !== $authResponse->getState()) {
            throw new InvalidStateException('Provided state does not match with session state');
        }

        return $handler->handle($request);
    }
}
