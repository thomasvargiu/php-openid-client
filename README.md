# php-openid-client

## Base implementation

```php

use TMV\OpenIdClient\Issuer;
use TMV\OpenIdClient\Client;
use TMV\OpenIdClient\Model\IssuerMetadata;
use TMV\OpenIdClient\Model\ClientMetadata;
use TMV\OpenIdClient\Authorization\AuthRequest;
use TMV\OpenIdClient\Provider\DiscoveryMetadataProvider;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\Core\JWKSet;
use Http\Discovery\Psr18ClientDiscovery;
use Http\Discovery\Psr17FactoryDiscovery;
use TMV\OpenIdClient\Service\AuthorizationService;

$discovery = new DiscoveryMetadataProvider();
$issuerMetadata = IssuerMetadata::fromClaims($discovery->discovery('https://example.com/.well-known/openid-configuration'));
$jkuFactory = new JKUFactory(
    Psr18ClientDiscovery::find(),
    Psr17FactoryDiscovery::findRequestFactory()
);

$issuer = new Issuer(
    $issuerMetadata,
    $jkuFactory->loadFromUrl($issuerMetadata->getJwksUri())
);

$clientMetadata = new ClientMetadata(
    'client_id', // client_id
    [] // other claims
);

$jwks =

$client = new Client(
    $issuer,
    $clientMetadata,
    new JWKSet([]),
    new AuthRequest(
        'client_id', // client_id
        'redirect_uri', // redirect URI
        [] // other params
    )
);

// Authorization

$authorizationService = new AuthorizationService();
$redirectAuthorizationUri = $authorizationService->getAuthorizationUri($client);


// Get access token

$responseMode = new \TMV\OpenIdClient\ResponseMode\Query();
$params = $responseMode->parseParams($serverRequest, $client);

$params = $authorizationService->fetchTokenFromCode($client, $params['code']);

$accessToken = $params['access_token'];

// Get user info

$userinfoService = new \TMV\OpenIdClient\Service\UserinfoService();
$userinfo = $userinfoService->getUserInfo($client, $accessToken);

```