# php-openid-client

**This library is under development**

Full OpenID client implementation.

[![Latest Stable Version](https://poser.pugx.org/thomasvargiu/php-openid-client/v/stable)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![Total Downloads](https://poser.pugx.org/thomasvargiu/php-openid-client/downloads)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![License](https://poser.pugx.org/thomasvargiu/php-openid-client/license)](https://packagist.org/packages/thomasvargiu/php-openid-client)
[![Code Coverage](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/build.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/build-status/master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/thomasvargiu/php-openid-client/?branch=master)


Most of the library code is based on the awesome [`node-openid-client`](https://github.com/panva/node-openid-client).


## Implemented specs and features

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749) & [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  - Authorization (Authorization Code Flow, Implicit Flow, Hybrid Flow)
  - UserInfo Endpoint and ID Tokens including Signing and Encryption (using the [JWT Framework](https://github.com/web-token/jwt-framework) library)
  - Passing a Request Object by Value or Reference including Signing and Encryption
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication incl. `client_secret_jwt` and `private_key_jwt` methods
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) and [RFC7591 OAuth 2.0 Dynamic Client Registration Protocol](https://tools.ietf.org/html/rfc7591)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [RFC7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)


### Supports of the following draft specifications

- [JWT Response for OAuth Token Introspection - draft 03](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-03)
- [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) - draft 02](https://openid.net/specs/openid-financial-api-jarm-wd-02.html)
- [OAuth 2.0 JWT Secured Authorization Request (JAR)](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-19)
- [OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens (MTLS) - draft 15](https://tools.ietf.org/html/draft-ietf-oauth-mtls-15)


## Installation

Requirements:
- `psr/http-client-implementation` implementation
- `psr/http-factory-implementation` implementation
- `psr/http-message-implementation` implementation

```
composer require thomasvargiu/php-openid-client
```

`RSA` signing algorithms are already included from the JWT Framework package`. 
If you need other algorithms you should install it manually.

## Basic Usage

For a basic usage you shouldn't require any other dependency package.

```php

use TMV\OpenIdClient\Client\Client;
use TMV\OpenIdClient\Issuer\IssuerFactory;
use TMV\OpenIdClient\Client\Metadata\ClientMetadata;
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
$redirectAuthorizationUri = $authorizationService->getAuthorizationUri(
    $client,
    ['login_hint' => 'user_username'] // custom params
);
// you can use this uri to redirect the user


// Get access token

/** @var ServerRequestInterface::class $serverRequest */
$serverRequest = null; // get your server request
$callbackParams = $authorizationService->getCallbackParams($serverRequest, $client);
$tokenSet = $authorizationService->callback($client, $callbackParams);

$idToken = $tokenSet->getIdToken(); // Unencrypted id_token
$accessToken = $tokenSet->getAccessToken(); // Access token
$refreshToken = $tokenSet->getRefreshToken(); // Refresh token

$claims = $tokenSet->claims(); // IdToken claims (if id_token is available)


// Refresh token
$tokenSet = $authorizationService->refresh($client, $tokenSet->getRefreshToken());


// Get user info

$userinfoService = new UserinfoService();
$userinfo = $userinfoService->getUserInfo($client, $tokenSet);

```

## Client registration

```php

use TMV\OpenIdClient\Service\RegistrationService;

$registration = new RegistrationService();

// registration
$metadata = $registration->register(
    $issuer,
    [
        'client_name' => 'My client name',
        'redirect_uris' => ['https://my-rp.com/callback'],
    ],
    'my-initial-token'
);

// read
$metadata = $registration->read($metadata['registration_client_uri'], $metadata['registration_access_token']);

// update
$metadata = $registration->update(
    $metadata['registration_client_uri'],
    $metadata['registration_access_token'],
    array_merge($metadata, [
        // new metadata
    ])
);

// delete
$registration->delete($metadata['registration_client_uri'], $metadata['registration_access_token']);

```


## Token Introspection

```php
use TMV\OpenIdClient\Service\IntrospectionService;

$service = new IntrospectionService();

$params = $service->introspect($client, $token);
```


## Token Revocation

```php
use TMV\OpenIdClient\Service\RevocationService;

$service = new RevocationService();

$params = $service->revoke($client, $token);
```
