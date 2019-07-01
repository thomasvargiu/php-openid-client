<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Authorization\TokenResponseInterface;
use TMV\OpenIdClient\ClientInterface;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Service\UserinfoService;

class UserInfoMiddleware implements MiddlewareInterface
{
    public const USERINFO_ATTRIBUTE = self::class;

    /** @var UserinfoService */
    private $userinfoService;
    /** @var ClientInterface */
    private $client;

    /**
     * TokenRequestMiddleware constructor.
     * @param UserinfoService $userinfoService
     * @param ClientInterface $client
     */
    public function __construct(
        UserinfoService $userinfoService,
        ClientInterface $client
    ) {
        $this->userinfoService = $userinfoService;
        $this->client = $client;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $tokenResponse = $request->getAttribute(TokenResponseInterface::class);

        if (! $tokenResponse instanceof TokenResponseInterface) {
            throw new RuntimeException('Unable to get token response attribute');
        }

        $accessToken = $tokenResponse->getAccessToken();

        if (! $accessToken) {
            throw new RuntimeException(sprintf(
                'Unable to get access token from "%s" attribute',
                TokenResponseInterface::class
            ));
        }

        $claims = $this->userinfoService->getUserInfo($this->client, $accessToken);

        return $handler->handle($request->withAttribute(static::USERINFO_ATTRIBUTE, $claims));
    }
}
