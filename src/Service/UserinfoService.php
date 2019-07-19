<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Service;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use function http_build_query;
use function is_array;
use function json_decode;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function sprintf;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Exception\InvalidArgumentException;
use TMV\OpenIdClient\Exception\OAuth2Exception;
use TMV\OpenIdClient\Exception\RuntimeException;
use TMV\OpenIdClient\Token\IdTokenVerifier;
use TMV\OpenIdClient\Token\IdTokenVerifierInterface;
use TMV\OpenIdClient\Token\TokenDecrypter;
use TMV\OpenIdClient\Token\TokenDecrypterInterface;
use TMV\OpenIdClient\Token\TokenSetInterface;

class UserinfoService
{
    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var IdTokenVerifierInterface */
    private $idTokenVerifier;

    /** @var TokenDecrypterInterface */
    private $idTokenDecrypter;

    public function __construct(
        ?ClientInterface $client = null,
        ?IdTokenVerifierInterface $idTokenVerifier = null,
        ?TokenDecrypterInterface $idTokenDecrypter = null,
        ?RequestFactoryInterface $requestFactory = null
    ) {
        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->idTokenVerifier = $idTokenVerifier ?: new IdTokenVerifier();
        $this->idTokenDecrypter = $idTokenDecrypter ?: new TokenDecrypter();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
    }

    public function getUserInfo(OpenIDClient $client, TokenSetInterface $tokenSet, bool $useBody = false): array
    {
        $accessToken = $tokenSet->getAccessToken();

        if (null === $accessToken) {
            throw new RuntimeException('Unable to get an access token from the token set');
        }

        $clientMetadata = $client->getMetadata();
        $issuerMetadata = $client->getIssuer()->getMetadata();

        $mTLS = true === $clientMetadata->get('tls_client_certificate_bound_access_tokens');

        $endpointUri = $issuerMetadata->getUserinfoEndpoint();

        if ($mTLS) {
            $endpointUri = $issuerMetadata->getMtlsEndpointAliases()['userinfo_endpoint'] ?? $endpointUri;
        }

        if (null === $endpointUri) {
            throw new InvalidArgumentException('Invalid issuer userinfo endpoint');
        }

        $expectJwt = null !== $clientMetadata->getUserinfoSignedResponseAlg()
            || null !== $clientMetadata->getUserinfoEncryptedResponseAlg()
            || null !== $clientMetadata->getUserinfoEncryptedResponseEnc();

        if ($useBody) {
            $request = $this->requestFactory->createRequest('POST', $endpointUri)
                ->withHeader('accept', $expectJwt ? 'application/jwt' : 'application/json')
                ->withHeader('content-type', 'application/x-www-form-urlencoded');
            $request->getBody()->write(http_build_query(['access_token' => $accessToken]));
        } else {
            $request = $this->requestFactory->createRequest('GET', $endpointUri)
                ->withHeader('accept', $expectJwt ? 'application/jwt' : 'application/json')
                ->withHeader('authorization', 'Bearer ' . $accessToken);
        }

        $httpClient = $client->getHttpClient() ?: $this->client;

        try {
            $response = $httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('Unable to get userinfo', 0, $e);
        }

        if (200 !== $response->getStatusCode()) {
            throw OAuth2Exception::fromResponse($response);
        }

        if ($expectJwt) {
            $token = $this->idTokenDecrypter->decryptToken($client, (string) $response->getBody(), 'userinfo');
            $payload = $this->idTokenVerifier->validateUserinfoToken($client, $token);
        } else {
            $payload = json_decode((string) $response->getBody(), true);
        }

        if (! is_array($payload)) {
            throw new RuntimeException('Unable to parse userinfo claims');
        }

        $idToken = $tokenSet->getIdToken();

        if (null === $idToken) {
            return $payload;
        }

        // check expected sub
        $expectedSub = $tokenSet->claims()['sub'] ?? null;

        if (! $expectedSub) {
            throw new RuntimeException('Unable to get sub claim from id_token');
        }

        if ($expectedSub !== ($payload['sub'] ?? null)) {
            throw new RuntimeException(
                sprintf('Userinfo sub mismatch, expected %s, got: %s', $expectedSub, $payload['sub'] ?? null)
            );
        }

        return $payload;
    }
}
