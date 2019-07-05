<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Authorization\AuthResponseInterface;
use TMV\OpenIdClient\Authorization\TokenResponseFactory;
use TMV\OpenIdClient\Authorization\TokenResponseFactoryInterface;
use TMV\OpenIdClient\Authorization\TokenResponseInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Service\AuthorizationService;

class TokenRequestMiddleware implements MiddlewareInterface
{
    /** @var AuthorizationService */
    private $authorizationService;

    /** @var TokenResponseFactoryInterface */
    private $tokenResponseFactory;

    /** @var null|ClientInterface */
    private $client;

    public function __construct(
        AuthorizationService $authorizationService,
        ?TokenResponseFactoryInterface $tokenResponseFactory = null,
        ?ClientInterface $client = null
    ) {
        $this->authorizationService = $authorizationService;
        $this->tokenResponseFactory = $tokenResponseFactory ?: new TokenResponseFactory();
        $this->client = $client;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authResponse = $request->getAttribute(AuthResponseInterface::class);
        $client = $this->client ?: $request->getAttribute(ClientInterface::class);

        if (! $client instanceof ClientInterface) {
            throw new LogicException('No OpenID client provided');
        }

        if (! $authResponse instanceof AuthResponseInterface) {
            throw new RuntimeException('Unable to get auth token response attribute');
        }

        $code = $authResponse->getCode();

        if (! $code) {
            throw new RuntimeException('Unable to get auth code');
        }

        $claims = $this->authorizationService->fetchTokenFromCode($client, $code);
        $tokenResponse = $this->tokenResponseFactory->createFromClaims($claims);

        return $handler->handle($request->withAttribute(TokenResponseInterface::class, $tokenResponse));
    }
}
