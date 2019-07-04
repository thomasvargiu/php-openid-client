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
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Service\AuthorizationService;

class TokenRequestMiddleware implements MiddlewareInterface
{
    /** @var AuthorizationService */
    private $authorizationService;

    /** @var ClientInterface */
    private $client;

    /** @var TokenResponseFactoryInterface */
    private $tokenResponseFactory;

    /**
     * TokenRequestMiddleware constructor.
     *
     * @param AuthorizationService $authorizationService
     * @param ClientInterface $client
     * @param null|TokenResponseFactoryInterface $tokenResponseFactory
     */
    public function __construct(
        AuthorizationService $authorizationService,
        ClientInterface $client,
        ?TokenResponseFactoryInterface $tokenResponseFactory = null
    ) {
        $this->authorizationService = $authorizationService;
        $this->client = $client;
        $this->tokenResponseFactory = $tokenResponseFactory ?: new TokenResponseFactory();
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authResponse = $request->getAttribute(AuthResponseInterface::class);

        if (! $authResponse instanceof AuthResponseInterface) {
            throw new RuntimeException('Unable to get auth token response attribute');
        }

        $code = $authResponse->getCode();

        if (! $code) {
            throw new RuntimeException('Unable to get auth code');
        }

        $claims = $this->authorizationService->fetchTokenFromCode($this->client, $code);
        $tokenResponse = $this->tokenResponseFactory->createFromClaims($claims);

        return $handler->handle($request->withAttribute(TokenResponseInterface::class, $tokenResponse));
    }
}
