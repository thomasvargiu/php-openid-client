<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Claims;

use function array_filter;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use function is_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;
use function TMV\OpenIdClient\check_server_response;
use TMV\OpenIdClient\Client\ClientInterface as OpenIDClient;
use TMV\OpenIdClient\Issuer\IssuerFactoryInterface;

final class DistributedParser extends AbstractClaims implements DistributedParserInterface
{
    /** @var ClientInterface */
    private $client;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?AlgorithmManager $algorithmManager = null,
        ?JWSVerifier $JWSVerifier = null,
        ?IssuerFactoryInterface $issuerFactory = null
    ) {
        parent::__construct($algorithmManager, $JWSVerifier, $issuerFactory);

        $this->client = $client ?: Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?: Psr17FactoryDiscovery::findRequestFactory();
    }

    public function fetch(OpenIDClient $client, array $claims, array $accessTokens = []): array
    {
        $claimSources = $claims['_claim_sources'] ?? null;
        $claimNames = $claims['_claim_names'] ?? null;

        if (! is_array($claimSources)) {
            return $claims;
        }

        if (! is_array($claimNames)) {
            return $claims;
        }

        $distributedSources = array_filter($claimSources, static function ($value) {
            return null !== ($value['endpoint'] ?? null);
        });

        /** @var ResponseInterface[] $responses */
        $responses = [];
        foreach ($distributedSources as $sourceName => $source) {
            $request = $this->requestFactory->createRequest('GET', (string) $source['endpoint'])
                ->withHeader('accept', 'application/jwt');

            $accessToken = $source['access_token'] ?? ($accessTokens[$sourceName] ?? null);
            if ($accessToken) {
                $request = $request->withHeader('authorization', 'Bearer ' . $accessToken);
            }

            try {
                $responses[$sourceName] = $this->client->sendRequest($request);
            } catch (Throwable $e) {
            }
        }

        $claimPayloads = [];
        foreach ($responses as $sourceName => $response) {
            try {
                check_server_response($response);
                $claimPayloads[$sourceName] = $this->claimJWT($client, (string) $response->getBody());
                unset($claims['_claim_sources'][$sourceName]);
            } catch (Throwable $e) {
            }
        }

        return $this->cleanClaims($this->assignClaims($claims, $claimNames, $claimPayloads));
    }
}
