<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Client\ClientInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Service\UserinfoService;
use TMV\OpenIdClient\Token\TokenSetInterface;

class UserInfoMiddleware implements MiddlewareInterface
{
    public const USERINFO_ATTRIBUTE = self::class;

    /** @var UserinfoService */
    private $userinfoService;

    /** @var null|ClientInterface */
    private $client;

    public function __construct(
        UserinfoService $userinfoService,
        ?ClientInterface $client = null
    ) {
        $this->userinfoService = $userinfoService;
        $this->client = $client;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $tokenSet = $request->getAttribute(TokenSetInterface::class);
        $client = $this->client ?: $request->getAttribute(ClientInterface::class);

        if (! $client instanceof ClientInterface) {
            throw new LogicException('No OpenID client provided');
        }

        if (! $tokenSet instanceof TokenSetInterface) {
            throw new RuntimeException('Unable to get token response attribute');
        }

        $claims = $this->userinfoService->getUserInfo($client, $tokenSet);

        return $handler->handle($request->withAttribute(static::USERINFO_ATTRIBUTE, $claims));
    }
}
