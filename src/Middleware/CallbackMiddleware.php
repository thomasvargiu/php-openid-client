<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Service\AuthorizationService;
use TMV\OpenIdClient\Session\AuthSessionInterface;
use TMV\OpenIdClient\Token\TokenSetInterface;

class CallbackMiddleware implements MiddlewareInterface
{
    /** @var AuthorizationService */
    private $authorizationService;

    /** @var string|null */
    private $redirectUri;

    /** @var null|ClientInterface */
    private $client;

    /** @var null|int */
    private $maxAge;

    public function __construct(
        AuthorizationService $authorizationService,
        ?ClientInterface $client = null,
        ?string $redirectUri = null,
        ?int $maxAge = null
    ) {
        $this->authorizationService = $authorizationService;
        $this->client = $client;
        $this->redirectUri = $redirectUri;
        $this->maxAge = $maxAge;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $client = $this->client ?: $request->getAttribute(ClientInterface::class);
        $authSession = $request->getAttribute(AuthSessionInterface::class);

        if (! $client instanceof ClientInterface) {
            throw new LogicException('No OpenID client provided');
        }

        if (null !== $authSession && ! $authSession instanceof AuthSessionInterface) {
            throw new LogicException('Invalid auth session provided in attribute ' . AuthSessionInterface::class);
        }

        $params = $this->authorizationService->getCallbackParams($request, $client);
        $tokenSet = $this->authorizationService->callback(
            $client,
            $params,
            $this->redirectUri,
            $authSession,
            $this->maxAge
        );

        return $handler->handle($request->withAttribute(TokenSetInterface::class, $tokenSet));
    }
}
