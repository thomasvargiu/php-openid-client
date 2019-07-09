<?php

declare(strict_types=1);

namespace TMV\OpenIdClientTest\functions;

use PHPUnit\Framework\TestCase;
use function TMV\OpenIdClient\normalize_webfinger;

class NormalizeWebfingerTest extends TestCase
{
    /**
     * @dataProvider normalizeProvider
     *
     * @param string $input
     * @param string $expected
     */
    public function testNormalize(string $input, string $expected): void
    {
        $this->assertSame($expected, normalize_webfinger($input));
    }

    public function normalizeProvider(): array
    {
        return [
            // email syntax
            ['foo@opemail.example.com', 'acct:foo@opemail.example.com'],
            // with issuer syntax
            ['https://opemail.example.com/joe', 'https://opemail.example.com/joe'],
            // hostname and port syntax
            ['ophp.example.com:8080', 'https://ophp.example.com:8080'],
            // act syntax
            ['acct:juliet%40capulet.example@opacct.example.com', 'acct:juliet%40capulet.example@opacct.example.com'],
        ];
    }
}
