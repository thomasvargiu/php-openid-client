<?php

declare(strict_types=1);

namespace TMV\OpenIdClient;

/**
 * @param string $input
 *
 * @return string
 */
function normalize_webfinger(string $input): string
{
    $hasScheme = static function (string $resource): bool {
        if (false !== \strpos($resource, '://')) {
            return true;
        }

        $authority = \explode('#', (string) \preg_replace('/(\/|\?)/', '#', $resource))[0];

        if (false === ($index = \strpos($authority, ':'))) {
            return false;
        }

        $hostOrPort = \substr($resource, $index + 1);

        return ! \preg_match('/^\d+$/', $hostOrPort);
    };

    $acctSchemeAssumed = static function (string $input): bool {
        if (false === \strpos($input, '@')) {
            return false;
        }

        $parts = \explode('@', $input);
        /** @var string $host */
        $host = \array_pop($parts);

        return ! \preg_match('/[:\/?]+/', $host);
    };

    if ($hasScheme($input)) {
        $output = $input;
    } elseif ($acctSchemeAssumed($input)) {
        $output = 'acct:' . $input;
    } else {
        $output = 'https://' . $input;
    }

    return \explode('#', $output)[0];
}
