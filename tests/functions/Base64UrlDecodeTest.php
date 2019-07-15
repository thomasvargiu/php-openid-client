<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\functions;

use PHPUnit\Framework\TestCase;
use function TMV\OpenIdClient\base64url_decode;

class Base64UrlDecodeTest extends TestCase
{
    public function testBase64UrlEncode(): void
    {
        static::assertSame('foo', base64url_decode('Zm9v'));
        static::assertSame('aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789', base64url_decode('YUJjRGVGZ0hpSmtMbU5vUHFSc1R1VndYeVowMTIzNDU2Nzg5'));
    }
}
