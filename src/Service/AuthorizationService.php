<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use JsonSerializable;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriFactoryInterface;
use TMV\OpenIdClient\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Model\AuthSessionInterface;
use function TMV\OpenIdClient\parse_callback_params;
use function TMV\OpenIdClient\parse_metadata_response;
use TMV\OpenIdClient\Token\ResponseTokenVerifier;
use TMV\OpenIdClient\Token\ResponseTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypter;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;
use TMV\OpenIdClient\Token\TokenSet;
use TMV\OpenIdClient\Token\TokenSetInterface;
use TMV\OpenIdClient\Token\TokenSetVerifier;
use TMV\OpenIdClient\Token\TokenSetVerifierInterface;

class AuthorizationService
{
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

    /**
     * AuthorizationService constructor.
     *
     * @param TokenSetVerifierInterface|null $tokenSetVerifier
     * @param ResponseTokenVerifierInterface|null $responseTokenVerifier
     * @param TokenDecrypterInterface|null $idTokenDecrypter
     * @param null|ClientInterface $client
     * @param null|RequestFactoryInterface $requestFactory
     * @param null|UriFactoryInterface $uriFactory
     */
    public function __construct(
        ?TokenSetVerifierInterface $tokenSetVerifier = null,
        ?ResponseTokenVerifierInterface $responseTokenVerifier = null,
        ?TokenDecrypterInterface $idTokenDecrypter = null,
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?UriFactoryInterface $uriFactory = null
    ) {
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

        $params = \array_filter(\array_merge([
            'client_id' => $clientMetadata->getClientId(),
            'scope' => 'openid',
            'response_type' => $clientMetadata->getResponseTypes()[0] ?? 'code',
            'redirect_uri' => $clientMetadata->getRedirectUris()[0] ?? null,
        ], $params));

        foreach ($params as $key => $value) {
            if (null === $value) {
                unset($params[$key]);
            } elseif ('claims' === $key && (\is_array($value) || $value instanceof JsonSerializable)) {
                $params['claims'] = \json_encode($value);
            } elseif (! \is_string($value)) {
                $params[$key] = (string) $value;
            }
        }

        if (empty($params['nonce']) && \in_array('id_token', \explode(' ', $params['response_type'] ?? ''), true)) {
            throw new InvalidArgumentException('nonce MUST be provided for implicit and hybrid flows');
        }

        return (string) $this->uriFactory->createUri($endpointUri)
            ->withQuery(\http_build_query($params));
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
        $tokenSet = TokenSet::fromParams($params);

        if ($params['id_token'] ?? null) {
            $params['id_token'] = $this->idTokenDecrypter->decryptToken($client, $params['id_token']);

            $tokenSet = TokenSet::fromParams($params);
            $this->tokenSetVerifier->validate($tokenSet, $client, $authSession, true, $maxAge);
        }

        if (! $tokenSet->getCode()) {
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

        if (! $code) {
            throw new RuntimeException('Unable to fetch token without a code');
        }

        if (! $redirectUri) {
            $redirectUri = $client->getMetadata()->getRedirectUris()[0] ?? null;
        }

        if (! $redirectUri) {
            throw new InvalidArgumentException('A redirect_uri should be provided');
        }

        $params = $this->grant($client, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ]);

        if (! ($params['id_token'] ?? null)) {
            return TokenSet::fromParams($params);
        }

        $params['id_token'] = $this->idTokenDecrypter->decryptToken($client, $params['id_token']);

        $authResponse = TokenSet::fromParams($params);
        $this->tokenSetVerifier->validate($authResponse, $client, $authSession, false, $maxAge);

        return $authResponse;
    }

    public function grant(OpenIDClient $client, array $params = []): array
    {
        $authMethod = $client->getAuthMethodFactory()
            ->create($client->getMetadata()->getTokenEndpointAuthMethod());

        $tokenRequest = $this->requestFactory->createRequest('POST', $client->getTokenEndpoint())
            ->withHeader('content-type', 'application/x-www-form-urlencoded');

        $tokenRequest = $authMethod->createRequest($tokenRequest, $client, $params);

        try {
            $response = $this->client->sendRequest($tokenRequest);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get token response', 0, $e);
        }

        return $this->processResponseParams($client, parse_metadata_response($response));
    }

    private function processResponseParams(OpenIDClient $client, array $params): array
    {
        if (\array_key_exists('error', $params)) {
            throw OAuth2Exception::fromParameters($params);
        }

        if (\array_key_exists('response', $params)) {
            $decrypted = $this->idTokenDecrypter->decryptToken($client, $params['response']);
            $params = $this->responseTokenVerifier->validate($client, $decrypted);
        }

        if (\array_key_exists('error', $params)) {
            throw OAuth2Exception::fromParameters($params);
        }

        return $params;
    }
}
