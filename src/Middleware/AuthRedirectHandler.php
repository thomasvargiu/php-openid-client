<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Authorization\AuthRequestInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Model\AuthSessionInterface;
use TMV\OpenIdClient\Service\AuthorizationService;

class AuthRedirectHandler implements RequestHandlerInterface
{
    /** @var AuthorizationService */
    private $authorizationService;

    /** @var ResponseFactoryInterface */
    private $responseFactory;

    /** @var null|ClientInterface */
    private $client;

    public function __construct(
        AuthorizationService $authorizationService,
        ?ResponseFactoryInterface $responseFactory = null,
        ?ClientInterface $client = null
    ) {
        $this->authorizationService = $authorizationService;
        $this->responseFactory = $responseFactory ?: Psr17FactoryDiscovery::findResponseFactory();
        $this->client = $client;
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authRequest = $request->getAttribute(AuthRequestInterface::class);

        if (! $authRequest instanceof AuthRequestInterface) {
            throw new RuntimeException('Unable to find a valid attribute for ' . AuthRequestInterface::class);
        }

        $authSession = $request->getAttribute(AuthSessionInterface::class);

        if ($authSession instanceof AuthSessionInterface) {
            if ($state = $authRequest->getState()) {
                $authSession->set('state', $state);
            } elseif ($state = $authSession->get('state')) {
                $authRequest = $authRequest->withParams(['state' => $state]);
            }

            if ($nonce = $authRequest->getNonce()) {
                $authSession->set('nonce', $nonce);
            } elseif ($nonce = $authSession->get('nonce')) {
                $authRequest = $authRequest->withParams(['nonce' => $nonce]);
            }
        }

        $client = $this->client ?: $request->getAttribute(ClientInterface::class);

        if (! $client instanceof ClientInterface) {
            throw new LogicException('No OpenID client provided');
        }

        $uri = $this->authorizationService->getAuthorizationUri($client, $authRequest->createParams());

        return $this->responseFactory->createResponse(302)
            ->withHeader('location', (string) $uri);
    }
}
