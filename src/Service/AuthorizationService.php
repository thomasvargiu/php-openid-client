<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use function array_filter;
use function array_key_exists;
use function array_merge;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use function http_build_query;
use function is_array;
use function is_string;
use function json_encode;
use JsonSerializable;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriFactoryInterface;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use function TMV\OpenIdClient\get_endpoint_uri;
use function TMV\OpenIdClient\parse_callback_params;
use function TMV\OpenIdClient\parse_metadata_response;
use TMV\OpenIdClient\Session\AuthSessionInterface;
use TMV\OpenIdClient\Token\ResponseTokenVerifier;
use TMV\OpenIdClient\Token\ResponseTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypter;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;
use TMV\OpenIdClient\Token\TokenSetFactory;
use TMV\OpenIdClient\Token\TokenSetFactoryInterface;
use TMV\OpenIdClient\Token\TokenSetInterface;
use TMV\OpenIdClient\Token\TokenSetVerifier;
use TMV\OpenIdClient\Token\TokenSetVerifierInterface;

/**
 * OAuth 2.0
 *
 * @link https://tools.ietf.org/html/rfc6749 RFC 6749
 */
class AuthorizationService
{
    /** @var TokenSetFactoryInterface */
    private $tokenSetFactory;

    /** @var TokenSetVerifierInterface */
    private $tokenSetVerifier;

    /** @var ResponseTokenVerifierInterface */
    private $responseTokenVerifier;

    /** @var TokenDecrypterInterface */
    private $idTokenDecrypter;

    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var UriFactoryInterface */
    private $uriFactory;

    public function __construct(
        ?TokenSetFactoryInterface $tokenSetFactory = null,
        ?TokenSetVerifierInterface $tokenSetVerifier = null,
        ?ResponseTokenVerifierInterface $responseTokenVerifier = null,
        ?TokenDecrypterInterface $idTokenDecrypter = null,
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    ) {
        $this->tokenSetFactory = $tokenSetFactory ?: new TokenSetFactory();
        $this->tokenSetVerifier = $tokenSetVerifier ?: new TokenSetVerifier();
        $this->responseTokenVerifier = $responseTokenVerifier ?: new ResponseTokenVerifier();
        $this->idTokenDecrypter = $idTokenDecrypter ?: new TokenDecrypter();
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
    }

    /**
     * @param OpenIDClient $client
     * @param array<string, mixed> $params
     *
     * @return string
     */
    public function getAuthorizationUri(OpenIDClient $client, array $params = []): string
    {
        $clientMetadata = $client->getMetadata();
        $issuerMetadata = $client->getIssuer()->getMetadata();
        $endpointUri = $issuerMetadata->getAuthorizationEndpoint();

        $params = array_merge([
            'client_id' => $clientMetadata->getClientId(),
            'scope' => 'openid',
            'response_type' => $clientMetadata->getResponseTypes()[0] ?? 'code',
            'redirect_uri' => $clientMetadata->getRedirectUris()[0] ?? null,
        ], $params);

        $params = array_filter($params, static function ($value) {
            return null !== $value;
        });

        foreach ($params as $key => $value) {
            if (null === $value) {
                unset($params[$key]);
            } elseif ('claims' === $key && (is_array($value) || $value instanceof JsonSerializable)) {
                $params['claims'] = json_encode($value);
            } elseif (! is_string($value)) {
                $params[$key] = (string) $value;
            }
        }

        if (! array_key_exists('nonce', $params) && 'code' !== ($params['response_type'] ?? '')) {
            throw new InvalidArgumentException('nonce MUST be provided for implicit and hybrid flows');
        }

        return (string) $this->uriFactory->createUri($endpointUri)
            ->withQuery(http_build_query($params));
    }

    public function getCallbackParams(ServerRequestInterface $serverRequest, OpenIDClient $client): array
    {
        return $this->processResponseParams($client, parse_callback_params($serverRequest));
    }

    public function callback(
        OpenIDClient $client,
        array $params,
        ?string $redirectUri = null,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): TokenSetInterface {
        $tokenSet = $this->tokenSetFactory->fromArray($params);

        $idToken = $tokenSet->getIdToken();

        if (null !== $idToken) {
            $tokenSet = $tokenSet->withIdToken($this->idTokenDecrypter->decryptToken($client, $idToken));
            $this->tokenSetVerifier->validate($tokenSet, $client, $authSession, true, $maxAge);
        }

        if (null === $tokenSet->getCode()) {
            return $tokenSet;
        }

        // get token
        return $this->fetchToken($client, $tokenSet, $redirectUri, $authSession, $maxAge);
    }

    public function fetchToken(
        OpenIDClient $client,
        TokenSetInterface $tokenSet,
        ?string $redirectUri = null,
        ?AuthSessionInterface $authSession = null,
        ?int $maxAge = null
    ): TokenSetInterface {
        $code = $tokenSet->getCode();

        if (null === $code) {
            throw new RuntimeException('Unable to fetch token without a code');
        }

        if (null === $redirectUri) {
            $redirectUri = $client->getMetadata()->getRedirectUris()[0] ?? null;
        }

        if (null === $redirectUri) {
            throw new InvalidArgumentException('A redirect_uri should be provided');
        }

        $tokenSet = $this->grant($client, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ]);

        $idToken = $tokenSet->getIdToken();

        if (null === $idToken) {
            return $tokenSet;
        }

        $tokenSet = $tokenSet->withIdToken($this->idTokenDecrypter->decryptToken($client, $idToken));
        $this->tokenSetVerifier->validate($tokenSet, $client, $authSession, false, $maxAge);

        return $tokenSet;
    }

    public function refresh(OpenIDClient $client, string $refreshToken, array $params = []): TokenSetInterface
    {
        $tokenSet = $this->grant($client, array_merge($params, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]));

        $idToken = $tokenSet->getIdToken();

        if (null === $idToken) {
            return $tokenSet;
        }

        $tokenSet = $tokenSet->withIdToken($this->idTokenDecrypter->decryptToken($client, $idToken));
        $this->tokenSetVerifier->validate($tokenSet, $client, null, false);

        return $tokenSet;
    }

    public function grant(OpenIDClient $client, array $params = []): TokenSetInterface
    {
        $authMethod = $client->getAuthMethodFactory()
            ->create($client->getMetadata()->getTokenEndpointAuthMethod());

        $endpointUri = get_endpoint_uri($client, 'token_endpoint');

        $tokenRequest = $this->requestFactory->createRequest('POST', $endpointUri)
            ->withHeader('content-type', 'application/x-www-form-urlencoded');

        $tokenRequest = $authMethod->createRequest($tokenRequest, $client, $params);

        try {
            $response = $this->client->sendRequest($tokenRequest);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get token response', 0, $e);
        }

        $params = $this->processResponseParams($client, parse_metadata_response($response));

        return $this->tokenSetFactory->fromArray($params);
    }

    private function processResponseParams(OpenIDClient $client, array $params): array
    {
        if (array_key_exists('error', $params)) {
            throw OAuth2Exception::fromParameters($params);
        }

        if (array_key_exists('response', $params)) {
            $decrypted = $this->idTokenDecrypter->decryptToken($client, $params['response']);
            $params = $this->responseTokenVerifier->validate($client, $decrypted);
        }

        if (array_key_exists('error', $params)) {
            throw OAuth2Exception::fromParameters($params);
        }

        return $params;
    }
}
