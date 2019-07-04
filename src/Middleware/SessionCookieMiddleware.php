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
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Model\AuthSession;
use TMV\OpenIdClient\Model\AuthSessionInterface;

class SessionCookieMiddleware implements MiddlewareInterface
{
    public const SESSION_ATTRIBUTE = AuthSessionInterface::class;

    /** @var string */
    private $cookieName;

    /** @var null|int */
    private $cookieMaxAge;

    /** @var int */
    private $randomBytes;

    public function __construct(string $cookieName, ?int $cookieMaxAge = null, int $randomBytes = 32)
    {
        $this->cookieName = $cookieName;
        $this->cookieMaxAge = $cookieMaxAge;
        $this->randomBytes = $randomBytes;
    }

    private function generateStateRandomBytes(): string
    {
        try {
            return \random_bytes($this->randomBytes);
        } catch (\Throwable $e) {
            throw new RuntimeException('Unable to generate random value for "state" parameter', 0, $e);
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $cookies = Cookies::fromRequest($request);
        $sessionCookie = $cookies->get($this->cookieName);

        $cookieValue = $sessionCookie ? $sessionCookie->getValue() : null;
        $data = $cookieValue ? \json_decode($cookieValue, true) : [];

        if (! \is_array($data)) {
            $data = [];
        }

        $authSession = new AuthSession();
        $authSession->set('state', $data['state'] ?? $this->generateStateRandomBytes());
        $authSession->set('nonce', $data['nonce'] ?? $this->generateStateRandomBytes());

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
