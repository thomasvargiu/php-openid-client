<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Middleware;

use Dflydev\FigCookies\Cookies;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\Modifier\SameSite;
use Dflydev\FigCookies\SetCookie;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TMV\OpenIdClient\Exception\LogicException;
use TMV\OpenIdClient\Model\AuthSession;
use TMV\OpenIdClient\Model\AuthSessionInterface;

class SessionCookieMiddleware implements MiddlewareInterface
{
    public const SESSION_ATTRIBUTE = AuthSessionInterface::class;

    /** @var string */
    private $cookieName;

    /** @var null|int */
    private $cookieMaxAge;

    public function __construct(string $cookieName = 'openid', ?int $cookieMaxAge = null)
    {
        $this->cookieName = $cookieName;
        $this->cookieMaxAge = $cookieMaxAge;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! \class_exists(Cookies::class)) {
            throw new LogicException('To use the SessionCookieMiddleware you should install dflydev/fig-cookies package');
        }

        $cookies = Cookies::fromRequest($request);
        $sessionCookie = $cookies->get($this->cookieName);

        $cookieValue = $sessionCookie ? $sessionCookie->getValue() : null;
        $data = $cookieValue ? \json_decode($cookieValue, true) : [];

        if (! \is_array($data)) {
            $data = [];
        }

        $authSession = AuthSession::fromArray($data);

        $response = $handler->handle($request->withAttribute(static::SESSION_ATTRIBUTE, $authSession));

        /** @var string $cookieValue */
        $cookieValue = \json_encode($authSession->jsonSerialize());

        $sessionCookie = SetCookie::create($this->cookieName)
            ->withValue($cookieValue)
            ->withMaxAge($this->cookieMaxAge)
            ->withHttpOnly()
            ->withSecure()
            ->withPath('/')
            ->withSameSite(SameSite::strict());

        $response = FigResponseCookies::set($response, $sessionCookie);

        return $response;
    }
}
