<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Authorization\AuthResponseFactory;
use TMV\OpenIdClient\Authorization\AuthResponseFactoryInterface;
use TMV\OpenIdClient\Authorization\AuthResponseInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\ResponseMode\ResponseModeProvider;
use TMV\OpenIdClient\ResponseMode\ResponseModeProviderInterface;

class AuthTokenResponseMiddleware implements MiddlewareInterface
{
    /** @var null|ClientInterface */
    private $client;

    /** @var AuthResponseFactoryInterface */
    private $authResponseFactory;

    /** @var null|ResponseModeProviderInterface */
    private $responseModeProvider;

    public function __construct(
        ?ClientInterface $client = null,
        ?AuthResponseFactoryInterface $authResponseFactory = null,
        ?ResponseModeProviderInterface $responseModeProvider = null
    ) {
        $this->client = $client;
        $this->authResponseFactory = $authResponseFactory ?: new AuthResponseFactory();
        $this->responseModeProvider = $responseModeProvider;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $client = $this->client ?: $request->getAttribute(ClientInterface::class);

        if (! $client instanceof ClientInterface) {
            throw new LogicException('No OpenID client provided');
        }

        $responseModeProvider = $this->responseModeProvider ?: new ResponseModeProvider(
            $client->getResponseModeFactory()
        );

        $responseMode = $responseModeProvider->getResponseMode($request);
        $claims = $responseMode->parseParams($request, $client);

        if (\array_key_exists('error', $claims)) {
            throw OAuth2Exception::fromParameters($claims);
        }

        $code = $claims['code'] ?? null;

        if (! $code) {
            throw new RuntimeException('Unable to find a code claim to make a token request');
        }

        $authResponse = $this->authResponseFactory->createFromClaims($claims);

        return $handler->handle($request->withAttribute(AuthResponseInterface::class, $authResponse));
    }
}
