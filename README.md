# php-openid-client

**This library is under development**

Full OpenID client implementation.


[![Latest Stable Version](https://poser.pugx.org/thomasvargiu/php-openid-client/v/stable)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![Total Downloads](https://poser.pugx.org/thomasvargiu/php-openid-client/downloads)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![License](https://poser.pugx.org/thomasvargiu/php-openid-client/license)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![Code Coverage](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/build.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/build-status/master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/?branch=master)

## Installation

```
composer require thomasvargiu/php-openid-client
```

## Base implementation

```php

use TMV\OpenIdClient\Client;
use TMV\OpenIdClient\IssuerFactory;
use TMV\OpenIdClient\Model\ClientMetadata;
use TMV\OpenIdClient\Service\AuthorizationService;
use TMV\OpenIdClient\Service\UserinfoService;
use Psr\Http\Message\ServerRequestInterface;

$issuerFactory = new IssuerFactory();
$issuer = $issuerFactory->fromUri('https://example.com/.well-known/openid-configuration');

$clientMetadata = new ClientMetadata(
    'client_id', // client_id
    // other claims
    [
        'redirect_uris' => [
            'https://my-rp.com/callback',    
        ],
    ]
);

$client = new Client($issuer, $clientMetadata);

// Authorization

$authorizationService = new AuthorizationService();
$redirectAuthorizationUri = $authorizationService->getAuthorizationUri($client);


// Get access token

/** @var ServerRequestInterface::class $serverRequest */
$serverRequest = null; // get your server request
$callbackParams = $authorizationService->getCallbackParams($serverRequest, $client);
$tokenSet = $authorizationService->callback($client, $callbackParams);

$idToken = $tokenSet->getIdToken(); // Unencrypted id_token
$accessToken = $tokenSet->getAccessToken(); // Access token
$refreshToken = $tokenSet->getRefreshToken(); // Refresh token

$claims = $tokenSet->claims(); // IdToken claims (if id_token is available)

// Get user info

$userinfoService = new UserinfoService();
$userinfo = $userinfoService->getUserInfo($client, $accessToken);

```